package engine

import (
	"context"
	"fmt"
	"nscan/common/argx"
	"nscan/plugins/common"
	"nscan/plugins/discover"
	"nscan/plugins/log"
	"nscan/plugins/poc/nucleis"
	"nscan/utils"
	"sync"
	"sync/atomic"
	"time"

	"github.com/malfunkt/iprange"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

var (
	defaultEngine        *engine
	pocEngine            *nuclei.ThreadSafeNucleiEngine
	pendingHandlerInited atomic.Bool
)

func init() {
	initPocEngine()
	initPocResultHandler()
	initPendingTaskHandler()
	defaultEngine = &engine{
		ScanTimeout:  time.Second * 10,
		Ratelimit:    100000,
		TaskParallel: 2,
	}
}

// todo more control args
// todo use Option func to set args
func NewEngine(scanTimeout time.Duration, rate uint32, taskParallel uint8) *engine {
	return &engine{ScanTimeout: scanTimeout, Ratelimit: rate, TaskParallel: taskParallel}
}

func Default() *engine {
	return defaultEngine
}

func (e *engine) Serve(enableManageFunc bool, addr ...string) error {
	return initRouter(enableManageFunc, addr...)
}

func (e *engine) Scan(taskId string, t Target) {
	var mu sync.Mutex
	mu.Lock()
	if !(e.TaskParallel == 0 || e.TaskParallel > RunningTaskCount()) {
		log.Logger.Info().Msgf("task[%s] pushed to pending queue", taskId)
		PendingTaskPool.Store(taskId, &Task{Target: t})
		mu.Unlock()
		return
	} else {
		mu.Unlock()
	}
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	task := Task{Active: true, Cancel: cancel}
	updateTask(taskId, &task)
	defer endTask(taskId)
	hosts := buildFinalHosts(t.Hosts)
	ports := buildFinalPorts(t.Ports)
	groups := utils.GroupStrsBySize(hosts, 1<<6)
	total := len(groups)
	progressStep := float64(1) / float64(total)
	for index, group := range groups {
		discoverEngine := discover.NewScanner()
		err := discoverEngine.Run(common.ScanInfo{
			Host:       group,
			Port:       ports,
			Ctx:        ctx,
			CancelFunc: cancel,
		})
		select {
		case <-ctx.Done():
			log.Logger.Warn().Msgf("Receive task end signal,task[%s] ends", taskId)
			goto END
		default:
			if err != nil {
				log.Logger.Error().Msgf("discover run with error:%s", err.Error())
				continue
			}
			var progressSubStep1 float64
			if len(discoverEngine.Targets) > 0 {
				progressSubStep1 = float64(1) / float64(len(discoverEngine.Targets))
			}
			for _, target := range discoverEngine.Targets {
				select {
				case <-ctx.Done():
					log.Logger.Warn().Msgf("Receive task end signal,task[%s] ends", taskId)
					goto END
				default:
					var progressSubStep2 float64
					if len(discoverEngine.Targets) > 0 {
						progressSubStep2 = float64(1) / float64(len(target.ServiceInfos))
					}
					for _, srvInfo := range target.ServiceInfos {
						select {
						case <-ctx.Done():
							log.Logger.Warn().Msgf("Receive task end signal,task[%s] ends", taskId)
							goto END
						default:
							var pocIds []string
							for _, tag := range srvInfo.Tags {
								if pocIds0, ok := nucleis.POCIdMappings[tag]; ok {
									pocIds = append(pocIds, pocIds0...)
								}
							}
							pocIds = utils.Deduplication(pocIds)
							if len(pocIds) == 0 {
								log.Logger.Debug().Msgf("no need to poc with [%s:%d]", target.IP, srvInfo.Port)
								task.Progress += progressStep * progressSubStep1 * progressSubStep2
								updateTask(taskId, &task)
								continue
							}
							doPocScan(ctx, srvInfo, target, pocIds)
						}
						task.Progress += progressStep * progressSubStep1 * progressSubStep2
						updateTask(taskId, &task)
					}
					if len(target.ServiceInfos) == 0 {
						task.Progress += progressStep * progressSubStep1
						updateTask(taskId, &task)
					}
				}

			}
		}
		progress := float64(index+1) / float64(total)
		task.Progress = progress
		updateTask(taskId, &task)
		log.Logger.Debug().Msgf("finished progress:%f", progress)
	}
END:
	log.Logger.Debug().Msgf("total cost %fs", time.Since(start).Seconds())
}

func initPendingTaskHandler() {
	if !pendingHandlerInited.Load() {
		go func() {
			ticker := time.NewTicker(time.Millisecond * 100)
			var mu sync.Mutex
			for {
				<-ticker.C
				mu.Lock()
				if RunningTaskCount() < defaultEngine.TaskParallel {
					// take out one task to scan
					taskId, task := popPendingTask()
					if taskId != "" && task != nil {
						go defaultEngine.Scan(taskId, task.Target)
					} else {
						if taskId != "" {
							endTask(taskId)
						}
					}
					mu.Unlock()
				} else {
					mu.Unlock()
				}
			}
		}()
	}
}

func initPocResultHandler() {
	go func() {
		pocEngine.GlobalResultCallback(func(event *output.ResultEvent) {
			log.Logger.Warn().Msgf("Found poc:%+v from [%s]", event.TemplateID, event.Matched)
		})
	}()
}

func buildFinalHosts(rawHosts []string) (hosts []string) {
	for _, host := range rawHosts {
		list, _ := iprange.ParseList(host)
		for _, ip := range list.Expand() {
			hosts = append(hosts, ip.String())
		}
	}
	return
}

func buildFinalPorts(rawPorts []string) (ports []string) {
	if len(rawPorts) == 0 {
		ports = CommonPorts
	} else {
		ports = rawPorts
	}
	return
}

func initPocEngine() {
	if pocEngine == nil {
		var err error
		pocEngine, err = nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), nuclei.DisableUpdateCheck())
		if err != nil {
			log.Logger.Error().Msgf("[POC] PoC Engine init faild")
			panic(err)
		} else {
			if argx.Verbose {
				log.Logger.Debug().Msgf("[POC] PoC Engine init successfully")
			}
		}
	}
}

func doPocScan(ctx context.Context, srvInfo common.ServiceInfo, target common.Target, pocIds []string) {
	var url string
	if srvInfo.Url != "" {
		url = srvInfo.Url
	} else {
		url = fmt.Sprintf("%s:%d", target.IP, srvInfo.Port)
	}
	pocEngine.ExecuteNucleiWithOptsCtx(ctx, []string{url}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: pocIds}))
}
