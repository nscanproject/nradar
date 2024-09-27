package poc

import (
	"net/url"
	"nscan/plugins/common"
	"nscan/plugins/poc/go/Springboot"
	"nscan/plugins/poc/go/ThinkPHP"
	"nscan/plugins/poc/go/confluence"
	"nscan/plugins/poc/go/f5"
	"nscan/plugins/poc/go/fastjson"
	"nscan/plugins/poc/go/gitlab"
	"nscan/plugins/poc/go/jboss"
	"nscan/plugins/poc/go/jenkins"
	"nscan/plugins/poc/go/jinher"
	"nscan/plugins/poc/go/landray"
	"nscan/plugins/poc/go/mcms"
	"nscan/plugins/poc/go/phpunit"
	"nscan/plugins/poc/go/seeyon"
	"nscan/plugins/poc/go/shiro"
	"nscan/plugins/poc/go/spark"
	"nscan/plugins/poc/go/sunlogin"
	"nscan/plugins/poc/go/tomcat"
	"nscan/plugins/poc/go/tongda"
	"nscan/plugins/poc/go/weblogic"
	"nscan/plugins/poc/go/xxljob"
	"nscan/plugins/poc/go/zabbix"
	"nscan/plugins/poc/go/zentao"
)

func POCcheck(techs []string, URL string, finalURL string) []common.VulnInfo {
	var HOST string
	var vulns []common.VulnInfo
	if host, err := url.Parse(URL); err == nil {
		HOST = host.Host
	}
	for tech := range techs {
		switch techs[tech] {
		case "Shiro", "shiro", "apache-shiro":
			key := shiro.CVE_2016_4437(finalURL)
			if key != "" {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2016_4437"})
			}
		case "Apache Tomcat", "apache-tomcat", "tomcat":
			// username, password := brute.Tomcat_brute(URL)
			// if username != "" {
			// 	vulns = append(vulns, fmt.Sprintf("Brute_Tomcat|%s:%s", username, password))
			// }
			if tomcat.CVE_2020_1938(HOST) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2020_1938"})
			}
			if tomcat.CVE_2017_12615(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2017_12615"})
			}
		case "Basic":
			// username, password := brute.Basic_brute(URL)
			// if username != "" {
			// 	vulns = append(vulns, fmt.Sprintf("Brute_basic|%s:%s", username, password))
			// }
		case "Weblogic", "WebLogic", "oracle-weblogic", "Weblogic Server":
			// username, password := brute.Weblogic_brute(URL)
			// if username != "" {
			// 	if username == "login_page" {
			// 		vulns = append(vulns, "Weblogic_login_page")
			// 	} else {
			// 		vulns = append(vulns, fmt.Sprintf("Brute_Weblogic|%s:%s", username, password))
			// 	}
			// }
			if weblogic.CVE_2014_4210(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2014_4210"})
			}
			if weblogic.CVE_2017_3506(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2017_3506"})
			}
			if weblogic.CVE_2017_10271(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2017_10271"})
			}
			if weblogic.CVE_2018_2894(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2018_2894"})
			}
			if weblogic.CVE_2019_2725(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2019_2725"})
			}
			if weblogic.CVE_2019_2729(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2019_2729"})
			}
			if weblogic.CVE_2020_2883(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2020_2883"})
			}
			if weblogic.CVE_2020_14882(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2020_14882"})
			}
			if weblogic.CVE_2020_14883(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2020_14883"})
			}
			if weblogic.CVE_2021_2109(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2021_2109"})
			}
		case "JBoss", "JBoss Application Server 7", "jboss", "jboss-as", "jboss-eap", "JBoss Web", "JBoss Application Server":
			if jboss.CVE_2017_12149(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2017_12149"})
			}
			// username, password := brute.Jboss_brute(URL)
			// if username != "" {
			// 	vulns = append(vulns, fmt.Sprintf("Brute_jboss|%s:%s", username, password))
			// }
		case "JSON", "alibaba-fastjson":
			fastjsonRceType := fastjson.Check(URL, finalURL)
			if fastjsonRceType != "" {
				vulns = append(vulns, common.VulnInfo{Name: "fastjson-RCE"})
			}
		case "Jenkins", "jenkins":
			if jenkins.Unauthorized(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "Jenkins Unauthorized script"})
			}
			if jenkins.CVE_2018_1000110(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2018_1000110"})
			}
			if jenkins.CVE_2018_1000861(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2018_1000861"})
			}
			if jenkins.CVE_2019_10003000(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2019_10003000"})
			}
		case "ThinkPHP", "thinkphp", "ThinkPHP YFCMF":
			if ThinkPHP.RCE(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "ThinkPHP-RCE"})
			}
		case "phpunit":
			if phpunit.CVE_2017_9841(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2017_9841"})
			}
		case "seeyon", "yonyou-seeyon-oa", "致远oa A6", "致远oa A8":
			if seeyon.SeeyonFastjson(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-fastjson-RCE"})
			}
			if seeyon.SessionUpload(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-session泄露&&文件上传获取shell"})
			}
			if seeyon.CNVD_2019_19299(URL) {
				vulns = append(vulns, common.VulnInfo{CNVD: "CNVD_2019_19299"})
			}
			if seeyon.CNVD_2020_62422(URL) {
				vulns = append(vulns, common.VulnInfo{CNVD: "CNVD_2020_62422"})
			}
			if seeyon.CNVD_2021_01627(URL) {
				vulns = append(vulns, common.VulnInfo{CNVD: "CNVD_2021_01627"})
			}
			if seeyon.CreateMysql(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-createMysql.jsp数据库敏感信息泄露"})
			}
			if seeyon.DownExcelBeanServlet(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-DownExcelBeanServlet用户敏感信息泄露"})
			}
			if seeyon.GetSessionList(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-getSessionList.jsp session泄露"})
			}
			if seeyon.InitDataAssess(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-initDataAssess.jsp 用户敏感信息泄露"})
			}
			if seeyon.ManagementStatus(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-A8 状态监控页面信息泄露"})
			}
			if seeyon.BackdoorScan(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "致远oa-植入后门"})
			}
		case "登录页面":
			// username, password, loginurl := brute.Admin_brute(finalURL)
			// if loginurl != "" {
			// 	vulns = append(vulns, fmt.Sprintf("Brute_admin|%s:%s", username, password))
			// }
		case "Sunlogin", "sunlogin":
			if sunlogin.SunloginRCE(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "Sunlogin-RCE"})
			}
		case "ZabbixSAML":
			if zabbix.CVE_2022_23131(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_23131"})
			}
		case "Spring", "Spring env", "spring-boot", "springboot", "spring-framework", "spring-boot-admin":
			if Springboot.CVE_2022_22965(finalURL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_22965"})
			}
		case "SpringGateway": //todo no identify
			if Springboot.CVE_2022_22947(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_22947"})
			}
		case "GitLab", "gitlab":
			if gitlab.CVE_2021_22205(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2021_22205"})
			}
		case "Confluence", "Atlassian Confluence":
			if confluence.CVE_2021_26084(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2021_26084"})
			}
			if confluence.CVE_2021_26085(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2021_26085"})
			}
			if confluence.CVE_2022_26134(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_26134"})
			}
			if confluence.CVE_2022_26138(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_26138"})
			}
		case "f5 Big IP":
			if f5.CVE_2020_5902(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2020_5902"})
			}
			if f5.CVE_2021_22986(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2021_22986"})
			}
			if f5.CVE_2022_1388(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_1388"})
			}
		case "禅道", "zentao-system":
			if zentao.CNVD_2022_42853(URL) {
				vulns = append(vulns, common.VulnInfo{CNVD: "CNVD_2022_42853"})
			}
		case "spark-jobs":
			if spark.CVE_2022_33891(URL) {
				vulns = append(vulns, common.VulnInfo{CVE: "CVE_2022_33891"})
			}
		case "蓝凌 OA", "蓝凌oa-ekp":
			if landray.Landray_RCE(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "蓝凌OA-RCE"})
			}
		case "通达OA", "通达oa", "tongda-oa":
			if tongda.Get_user_session(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "通达OA-V11.6 任意用户登陆"})
			}
			if tongda.File_delete(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "通达OA-V11.6 任意文件删除"})
			}
			if tongda.File_upload(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "通达OA-V11.8 api.ali.php 任意文件上传"})
			}
		case "铭飞MCms", "MCMS-铭飞":
			if mcms.Front_Sql_inject(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "MCMS-铭飞-/cms/content/list SQL注入漏洞"})
			}
		case "xxl-job":
			if xxljob.Default_Token_Rce(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "xxl-job-默认token-RCE"})
			}
		case "金和协同管理平台":
			if jinher.Check(URL) {
				vulns = append(vulns, common.VulnInfo{Name: "金和协同管理平台-Sql注入漏洞"})
			}
		}
		// if checklog4j {
		// 	if log4j.Check(URL, finalURL) {
		// 		vulns = append(vulns, common.VulnInfo{Name: "log4j漏洞"})
		// 	}
		// }
	}

	return vulns
}
