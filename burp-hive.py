from burp import IBurpExtender, IContextMenuFactory, ITab 
from burp import IHttpRequestResponse
from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList
from javax.swing import JMenuItem, JMenu
from java.net import URL
import threading
import httplib
import struct
import json
import sys
import socket

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.cookie = ""
        self.projectName = ""
        self.activeProjectId = ""
        self.activeProjectName = ""
        self.ServerURL = ""
        self.appsList = {}
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Hive Burp extension")
        callbacks.registerContextMenuFactory(self)
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())
        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        # Vertical of serv options
        boxServOpt = swing.Box.createVerticalBox()

        # Server Option title
        boxServOpt.add(swing.JLabel("Server Options:"))
        boxServOpt.add(swing.Box.createVerticalStrut(10))
        # =====Server cookies option start====
        CookieOpt = swing.Box.createHorizontalBox()
        ## Title
        CookieOpt.add(swing.JLabel("Token:         "))
        CookieOpt.add(swing.Box.createHorizontalStrut(10))
        ## cookie value
        self.CookieField = swing.JTextField("BSESSIONID cookie value",60)
        self.CookieField = swing.JTextField("06ffe688-fb5c-43f8-97d6-965e2785cf7a",60)
        CookieOpt.add(self.CookieField)
        CookieOpt.add(swing.Box.createHorizontalStrut(10))
        ## SET button
        CookieOpt.add(swing.JButton('Set', actionPerformed=self.setCookie))
        CookieOpt.add(swing.Box.createHorizontalStrut(10))
        ## Current value
        self.textCookieValue = swing.JLabel(self.CookieField.getText())
        CookieOpt.add(self.textCookieValue)
        ## Put all this on the screen
        boxServOpt.add(CookieOpt)
        boxServOpt.add(swing.Box.createVerticalStrut(10))
        # =====Server cookies option end====

        # =====Server URL option start====
        BoxservURLopt = swing.Box.createHorizontalBox()
        ## Title
        BoxservURLopt.add(swing.JLabel("Server URL:"))
        BoxservURLopt.add(swing.Box.createHorizontalStrut(10))
        ## hostname
        # self.ServerURLField = swing.JTextField("127.0.0.1",60)
        self.ServerURLField = swing.JTextField("demohive.hexway.io",60)
        BoxservURLopt.add(self.ServerURLField)
        BoxservURLopt.add(swing.Box.createHorizontalStrut(10))
        ## SET button
        BoxservURLopt.add(swing.JButton('Set', actionPerformed=self.setServerURL))
        BoxservURLopt.add(swing.Box.createHorizontalStrut(10))
        ## Current value
        self.textServerURL = swing.JLabel(self.ServerURLField.getText())
        BoxservURLopt.add(self.textServerURL)
        BoxservURLopt.add(swing.Box.createHorizontalStrut(10))
        ## Put all this on the screen
        boxServOpt.add(BoxservURLopt)
        boxServOpt.add(swing.Box.createVerticalStrut(10))
        # =====Server URL option end====

        # =====Server projects option start====
        ProjectNameOpt = swing.Box.createHorizontalBox()
        projects = []
        ## Title
        ProjectNameOpt.add(swing.JLabel("Project:       "))
        ProjectNameOpt.add(swing.Box.createHorizontalStrut(10))
        ## project name
        self.projectName = swing.JComboBox(projects)
        ProjectNameOpt.add(self.projectName)
        ProjectNameOpt.add(swing.Box.createHorizontalStrut(10))
        ## SET button
        ProjectNameOpt.add(swing.JButton('Set', actionPerformed=self.setProject))
        ProjectNameOpt.add(swing.Box.createHorizontalStrut(10))
        ## Current value
        self.textProjectName = swing.JLabel(self.projectName.getSelectedItem())
        ProjectNameOpt.add(self.textProjectName)
        ProjectNameOpt.add(swing.Box.createHorizontalStrut(10))
        ## Put all this on the screen
        boxServOpt.add(ProjectNameOpt)
        boxServOpt.add(swing.Box.createVerticalStrut(10))
        # =====Server projects option end====

        # =====Server projects option start====
        GetAllrequestsBox = swing.Box.createHorizontalBox()
        projects = []
        ## Title
        # GetAllrequestsBox.add(swing.JLabel("Label title"))
        # GetAllrequestsBox.add(swing.Box.createHorizontalStrut(10))
        ## SET button
        GetAllrequestsBox.add(swing.JButton('Send all Issues to Repeater', actionPerformed=self.sendAllIssuesToRepeater))
        GetAllrequestsBox.add(swing.Box.createHorizontalStrut(10))
        ## Put all this on the screen
        boxServOpt.add(GetAllrequestsBox)
        boxServOpt.add(swing.Box.createVerticalStrut(10))
        # =====Server projects option end====

        # # =====Server application option start====
        # AppNameOpt = swing.Box.createHorizontalBox()
        # apps = []
        # ## Title
        # AppNameOpt.add(swing.JLabel("Application:"))
        # AppNameOpt.add(swing.Box.createHorizontalStrut(10))
        # ## app name
        # self.appName = swing.JComboBox(apps)
        # AppNameOpt.add(self.appName)
        # AppNameOpt.add(swing.Box.createHorizontalStrut(10))
        # ## SET button
        # AppNameOpt.add(swing.JButton('Set', actionPerformed=self.setApp))
        # AppNameOpt.add(swing.Box.createHorizontalStrut(10))
        # ## Current value
        # self.textAppName = swing.JLabel(self.appName.getSelectedItem())
        # AppNameOpt.add(self.textAppName)
        # AppNameOpt.add(swing.Box.createHorizontalStrut(10))
        # # Put all this on the screen
        # boxServOpt.add(AppNameOpt)
        # boxServOpt.add(swing.Box.createVerticalStrut(10))
        # # =====Server application option end====
        # Show all the options
        textPanel.add(boxServOpt)
       #
       #  boxHorizontal.add(swing.JButton('Do something!', actionPerformed=self.addSitemap))
       #  boxVertical.add(boxHorizontal)
       #  textPanel.add(boxVertical)


        self.tab.add(textPanel, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)
        return
    
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Hive"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def createMenuItems(self, invocation):
        self.context = invocation
        warning_config_plugin = "Configure Hive extension. Set token, url, project"
        add_host_str = "Send hostname:port"
        add_sitemap = "Send sitemap"
        add_issue_as_record = "Add issue as a record"
        create_issue = "Create issue"
        create_issue_from_message = "Create issue from Request/Response"
        send_req_resp =  "Send Request/Response"
        is_target_tree = invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE
        is_message_editor_req = invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST
        is_message_editor_rsp = invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
        is_message_viewer_req = invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        is_message_viewer_rsp = invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
        is_proxy_history = invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY
        is_site_map_tree = invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE
        is_search_results = invocation.getInvocationContext() == invocation.CONTEXT_SEARCH_RESULTS
        is_scanner_results = invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS

        if not self.activeProjectName:
            menuList = ArrayList()
            configureHive= JMenuItem(warning_config_plugin)
            menuList.add(configureHive)
            return menuList
        elif is_target_tree:
            menuList = ArrayList()
            HostmenuItem = JMenuItem(add_host_str, actionPerformed=self.sendHost)
            sendSiteMapItem = JMenuItem(add_sitemap, actionPerformed=self.sendAllURIs)
            menuList.add(HostmenuItem)
            menuList.add(sendSiteMapItem)
            return menuList
        elif is_message_editor_req or is_message_editor_req or is_message_editor_rsp or is_message_viewer_req or is_message_viewer_rsp or  is_proxy_history or is_site_map_tree or is_search_results:
            menuList = ArrayList()
            HostmenuItem = JMenuItem(add_host_str, actionPerformed=self.sendHost)
            createIssueFromMsgMenuItem = JMenuItem(create_issue_from_message, actionPerformed=self.createIssueFromMessage)
            sendReqtoHiveItem = JMenuItem(send_req_resp, actionPerformed=self.sendOneUri)
            menuList.add(HostmenuItem)
            menuList.add(sendReqtoHiveItem)
            menuList.add(createIssueFromMsgMenuItem)
            return menuList
        elif is_scanner_results:
            menuList = ArrayList()
            IssuemenuItem = JMenuItem(create_issue, actionPerformed=self.sendIssues)
            RecordmenuItem = JMenuItem(add_issue_as_record, actionPerformed=self.sendRecord)
            sendReqtoHiveItem = JMenuItem(send_req_resp, actionPerformed=self.sendOneUri)
            menuList.add(sendReqtoHiveItem)
            menuList.add(IssuemenuItem)
            menuList.add(RecordmenuItem)
            return menuList
        else:
            menuList = ArrayList()
            HostmenuItem = JMenuItem(add_host_str, actionPerformed=self.sendHost)
            # RecordmenuItem = JMenuItem(add_issue_as_record, actionPerformed=self.sendRecord)
            # IssuemenuItem = JMenuItem(create_issue, actionPerformed=self.sendIssues)
            # createIssueFromMsgMenuItem = JMenuItem(create_issue_from_message, actionPerformed=self.createIssueFromMessage)
            sendReqtoHiveItem = JMenuItem(send_req_resp, actionPerformed=self.sendOneUri)
            # sendSiteMapItem = JMenuItem(add_sitemap, actionPerformed=self.sendAllURIs)
            menuList.add(HostmenuItem)
            # menuList.add(RecordmenuItem)
            menuList.add(sendReqtoHiveItem)
            # menuList.add(IssuemenuItem)
            # menuList.add(createIssueFromMsgMenuItem)
            # menuList.add(sendSiteMapItem)
            return menuList

    def sendRecord(self, event):
        print ("in sendRecord")
        self.fromScope = False
        t = threading.Thread(target=self.workWithRecords)
        t.daemon = True
        t.start()

    def sendIssues(self, event):
        print ("in sendIssues")
        self.fromScope = False
        t = threading.Thread(target=self.workWithIssues)
        t.daemon = True
        t.start()

    def createIssueFromMessage(self, event):
        print ("in createIssueFromMessage")
        self.fromScope = False
        t = threading.Thread(target=self.workCreateIssueFromMessage)
        t.daemon = True
        t.start()

    def sendHost(self, event):
        print ("in sendHost")
        self.fromScope = False
        t = threading.Thread(target=self.workWithHost)
        t.daemon = True
        t.start()

    def sendOneUri(self, event):
        print ("in sendOneUri")
        self.fromScope = False
        detailed = True
        t = threading.Thread(target=self.workWithURI, args=(detailed,))
        t.daemon = True
        t.start()

    def sendAllURIs(self, event):
        print ("in sendAllURIs")
        self.fromScope = True
        detailed = True
        t = threading.Thread(target=self.workWithSitemap, args=(detailed,))
        t.daemon = True
        t.start()

    def workWithHost(self):
        print("In workWithHost")
        httpTraffic = self.context.getSelectedMessages()
        for traffic in httpTraffic:
            hostname = traffic.getHttpService().getHost()
            port = traffic.getHttpService().getPort()
            ip = socket.gethostbyname(hostname)
            if not ip:
                print("{}:{}".format(hostname,port))
            else:
                print("{}:{}:{}".format(ip,hostname, port))
                self.addHostToHive(ip,hostname,port)

    def getCriticality(self, BurpLevel):
        if BurpLevel == "High":
            return 3
        elif BurpLevel == "Medium":
            return 2
        else:
            return 1

    def workWithRecords(self):
        # Add info into host records
        print("In workWithRecords")
        if not self.activeProjectId or not self.ServerURL:
            print("Error! Need to know project name and ServerURL !")
            return
        issues = self.context.getSelectedIssues()
        for issue in issues:
            hostname = issue.getHttpService().getHost()
            ip = socket.gethostbyname(hostname)
            port = issue.getHttpService().getPort()
            # Add host
            self.addHostToHive(ip,hostname,port)
            # Create issue as a record
            # [
            #     {
            #         "ipv4": "192.168.1.1",
            #         "hostnames": [
            #             {
            #                 "hostname": "unit.test.com"
            #             }
            #         ],
            #         "ports": [
            #             {
            #                 "port": 443,
            #                 "service": {
            #                     "name": "http",
            #                     "product": "
            #                 },
            #                 "protocol": "tcp",
            #                 "state": "open",
            #                 "records": [
            #                     {
            #                         "name": "TLS cookie without secure flag set",
            #                         "tool_name": "Burp",
            #                         "record_type": "nested",
            #                         "value": [
            #                             {
            #                                 "name": "Issue detail",
            #                                 "record_type": "text_block",
            #                                 "value": "Unit test vuln name"
            #                             },
            #                             {
            #                                 "name": "Issue background",
            #                                 "record_type": "text_block",
            #                                 "value": "Unit test vuln info"
            #                             },
            #                             {
            #                                 "name": "Issue remediation",
            #                                 "record_type": "text_block",
            #                                 "value": "Unit test vuln info"
            #                             },
            #                             {
            #                                 "name": "Vulnerability classifications",
            #                                 "record_type": "list",
            #                                 "value": [
            #                                     "CVE-2020-2020",
            #                                     "URL-https://unit.test.com/vuln"
            #                                 ]
            #                             }
            #                         ]
            #                     }
            #                 ]
            #             }
            #         ]
            #     }
            # ]
            issue_target = [{'ipv4': '',
                             'hostnames': [{'hostname': ''}],
                             'ports': [{'port': 443,
                                        'service': {'name': '', 'product': ''},
                                        'protocol': 'tcp',
                                        'state': 'open',
                                        'records':[]
                                        }]}
                            ]
            issue_record ={'name': '',
                           'tool_name': 'Burp',
                           'record_type': 'nested',
                           'value': [{'name': 'Issue detail',
                                      'record_type': 'text_block',
                                      'value': ''},
                                     {'name': 'Issue background',
                                      'record_type': 'text_block',
                                      'value': ''},
                                     {'name': 'Issue remediation',
                                      'record_type': 'text_block',
                                      'value': ''},
                                     {'name': 'URL',
                                      'record_type': 'string',
                                      'value': ''},
                                     {'name': 'Request',
                                      'record_type': 'codeblock',
                                      'value': ''},
                                     {'name': 'Response',
                                      'record_type': 'codeblock',
                                      'value': ''}

                                     ]}
            issue_target[0]["ipv4"]=ip
            issue_target[0]["hostnames"][0]["hostname"] = hostname
            issue_target[0]["ports"][0]["port"] = int(port)
            issue_target[0]["ports"][0]["service"]["name"] = "https"
            issue_record["name"] = "[{}] {}".format(issue.getSeverity(), issue.getIssueName())
            issue_record["value"][0]["value"] = issue.getIssueDetail()
            issue_record["value"][1]["value"] = issue.getIssueBackground()
            issue_record["value"][2]["value"] = issue.getRemediationDetail()
            issue_record["value"][3]["value"] = str(issue.getUrl())
            issue_record["value"][4]["value"] = b''.join([self.int_to_bytes(x) for x in issue.getHttpMessages()[0].getRequest()]).decode('utf-8') if issue.getHttpMessages()[0].getRequest() else ""
            issue_record["value"][5]["value"] = b''.join([self.int_to_bytes(x) for x in issue.getHttpMessages()[0].getResponse()]).decode('utf-8')[:4000] if issue.getHttpMessages()[0].getResponse() else ""
            # issue_record["value"][5]["value"] = "".join(map(chr, issue.getHttpMessages()[0].getResponse()))[:4000] if issue.getHttpMessages()[0].getResponse() else ""
            issue_target[0]["ports"][0]["records"].append(issue_record)
            print(issue_target)
            headers = {"Content-Type": "application/json",
                       "Cookie": "BSESSIONID={}".format(self.cookie)
                       }
            conn = httplib.HTTPConnection(self.ServerURL)
            conn.request("POST", "/api/project/{}/graph/api".format(self.activeProjectId), json.dumps(issue_target), headers)
            response = conn.getresponse()
            responseStatus = response.status
            respData = response.read()
            print(responseStatus, respData)
            if responseStatus == 200:
                print("OK add record")
                # # print("OK: {}".format(respData))
                # # Now let's add req/resp to the issue
                # issueID = json.loads(respData)[0]['id']
                # for reqresp in issue.getHttpMessages():
                #     req = reqresp.getRequest()
                #     resp = reqresp.getResponse()
                #     ("ok1")
                #     req_data=[{"request":"".join(map(chr, req)),
                #               "response":"".join(map(chr, resp)),
                #               "nodeId":issueID}
                #     ]
                #     headers = {"Content-Type": "application/json",
                #                "Cookie": "BSESSIONID={}".format(self.cookie)
                #                }
                #     conn = httplib.HTTPConnection(self.ServerURL)
                #     conn.request("POST", "/api/project/{}/graph/nodes".format(self.activeProjectId), json.dumps(req_data),
                #                  headers)
                #     response = conn.getresponse()
                #     responseStatus = response.status
                #     respData = response.read()
                #     if responseStatus == 200:
                #         print("OK")
                #     else:
                #         print("Something wrong: {}".format(responseStatus))
            else:
                print("Something wrong: {}".format(responseStatus))

    def workWithIssues(self):
        # Add info into issues
        print("In workWithIssues")
        if not self.activeProjectId or not self.ServerURL:
            print("Error! Need to know project name and ServerURL !")
            return
        issues = self.context.getSelectedIssues()
        for issue in issues:
            hostname = issue.getHttpService().getHost()
            ip = socket.gethostbyname(hostname)
            port = issue.getHttpService().getPort()
            # Add host
            self.addHostToHive(ip,hostname,port)
            # Create issue
            issue_data = [{
                "nodeId":None,
                "issueName": issue.getIssueName(),
                "criticalityScore": self.getCriticality(issue.getSeverity()),
                "probabilityScore": 2,
                "generalDescription": issue.getIssueDetail(),
                "recommendations": issue.getRemediationBackground(),
                "reproduceDescription": "",
                "risksDescription": issue.getIssueBackground(),
                "status": "new",
                "technicalDescription": "Vulnerable URL: `{}`".format(str(issue.getUrl())),
                "weaknessType": "",
                "hostnames":[hostname],
                "ips":[ip],
            }]
            print(json.dumps(issue_data))
            headers = {"Content-Type": "application/json",
                       "Cookie": "BSESSIONID={}".format(self.cookie)
                       }
            conn = httplib.HTTPConnection(self.ServerURL)
            conn.request("POST", "/api/project/{}/graph/nodes".format(self.activeProjectId), json.dumps(issue_data), headers)
            response = conn.getresponse()
            responseStatus = response.status
            respData = response.read()
            if responseStatus == 200:
                # print("OK: {}".format(respData))
                # Now let's add req/resp to the issue
                issueID = json.loads(respData)[0]['id']
                for reqresp in issue.getHttpMessages():
                    req = reqresp.getRequest()
                    resp = reqresp.getResponse()
                    ("ok1")
                    req_data=[{"request":b''.join([self.int_to_bytes(x) for x in req]).decode('utf-8'),
                              "response":b''.join([self.int_to_bytes(x) for x in resp]).decode('utf-8'),
                              "nodeId":issueID}
                    ]
                    headers = {"Content-Type": "application/json",
                               "Cookie": "BSESSIONID={}".format(self.cookie)
                               }
                    conn = httplib.HTTPConnection(self.ServerURL)
                    conn.request("POST", "/api/project/{}/graph/nodes".format(self.activeProjectId), json.dumps(req_data),
                                 headers)
                    response = conn.getresponse()
                    responseStatus = response.status
                    respData = response.read()
                    if responseStatus == 200:
                        print("OK")
                    else:
                        print("Something wrong: {}".format(responseStatus))
            else:
                print("Something wrong: {}".format(responseStatus))

    def doSearch(self, query):
        print("in doSearch")
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        data = {"searchString":query}
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("POST", "/api/project/{}/graph/search".format(self.activeProjectId), json.dumps(data), headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = response.read()
            # print("OK: {}".format(respBody))
            resp = json.loads(respBody)
            return resp
        else:
            print(response.status)
            return ""

    def int_to_bytes(self, number):
        # print("in int_to_bytes")
        rez  = struct.pack("<b", int(number))
        # print(rez)
        return rez

    def workWithSitemap(self, detailed = False):
        print("In workWithSitemap")
        hostUrls = {}
        traffic = self.context.getSelectedMessages()[0]
        httpService = traffic.getHttpService()
        selectedHostPort = "{}://{}:{}".format(httpService.getProtocol(),httpService.getHost(),httpService.getPort())
        SelectedUri = str(traffic.getUrl())
        print(SelectedUri)
        selectedHost = "{}://{}".format(httpService.getProtocol(),httpService.getHost())
        siteMapData = self.callbacks.getSiteMap(selectedHost)
        hostIP=socket.gethostbyname(httpService.getHost())
        addedAsset=[]
        for entry in siteMapData:
            try:
                line_request = line_response = ""
                requestInfo = self.helpers.analyzeRequest(entry)
                url = requestInfo.getUrl()
                # print(url)
                try:
                    decodedUrl = self.helpers.urlDecode(str(url))
                except Exception as e:
                    continue
                # print(decodedUrl)
                # print(SelectedUri)
                if decodedUrl.startswith(SelectedUri):
                    uri = decodedUrl.replace(selectedHostPort,"")
                    # urllist.append(uri)
                    if entry.getRequest() and detailed:
                        print("has getRequest")
                        # line_request = "".join(map(chr, traffic.getRequest()))
                        line_request = b''.join([self.int_to_bytes(x) for x in entry.getRequest()]).decode('utf-8')
                        # print(line_request)
                    if entry.getResponse() and detailed:
                        print("has getResponse")
                        line_response = b''.join([self.int_to_bytes(x) for x in entry.getResponse()]).decode('utf-8')
                    hostUrls[uri]={'request':line_request,'response':line_response, 'uri':uri, 'hostname':httpService.getHost(), 'port':httpService.getPort(), 'ip':hostIP}
                    # print(hostUrls[uri])
                    # check if  host, ip, port exist, skip next steps
                    host_ip=socket.gethostbyname(traffic.host)
                    query = 'ip== ' + host_ip + ' and port == ' + str(traffic.port)+' and hostname == "'+traffic.host+'"'
                    if traffic.host in addedAsset:
                        print("Already have host: {}, ip:{}, port:{} in Hive".format(traffic.host, host_ip, traffic.port))
                        pass
                    elif self.doSearch(query):
                        print("Already have host: {}, ip:{}, port:{} in Hive".format(traffic.host, host_ip, traffic.port))
                        pass
                    else:
                        addedAsset.append(traffic.host)
                        # addedAsset.append({traffic.host:{"host":traffic.host,"ip":host_ip,"port":traffic.port}})
                        t2 = threading.Thread(target=self.addPort, args=(traffic,))
                        t2.daemon = True
                        t2.start()
            except UnicodeEncodeError:
                print("Unicode error!")
                continue
        t = threading.Thread(target=self.sendURLToHive, args=(hostUrls,detailed,))
        t.daemon = True
        t.start()

    def workWithURI(self, detailed =False):
        print ("In workWithURI. Detailed = {}".format(detailed))
        httpTraffic = self.context.getSelectedMessages()
        hostUrls = {}
        for traffic in httpTraffic:
            try:
                line_request = line_response = ""
                httpService = traffic.getHttpService()
                host = "{}://{}:{}".format(httpService.getProtocol(),httpService.getHost(),httpService.getPort())
                uri = str(traffic.getUrl()).replace(host,"")
                print("uri:{}".format(uri))
                if traffic.getRequest():
                    print("has getRequest")
                    # line_request = "".join(map(chr, traffic.getRequest()))
                    line_request = b''.join([self.int_to_bytes(x) for x in traffic.getRequest()]).decode('utf-8')
                    print(line_request)
                if traffic.getResponse():
                    print("has getResponse")
                    line_response = b''.join([self.int_to_bytes(x) for x in traffic.getResponse()]).decode('utf-8')
                    # line_response = "ABC"
                    # print(line_response)
                    # line_response = "".join(map(chr, traffic.getResponse()))
                    # print("3333")
                hostUrls[uri]={'request':line_request,'response':line_response, 'uri':uri, 'hostname':httpService.getHost(), 'port':httpService.getPort(), 'ip':socket.gethostbyname(httpService.getHost())}
                print(hostUrls[uri])
                t2 = threading.Thread(target=self.addPort, args=(traffic,))
                t2.daemon = True
                t2.start()
            except UnicodeEncodeError:
                print("Unicode error!")
                continue
        # urllist = []
        # siteMapData = self.callbacks.getSiteMap(None)
        # for entry in siteMapData:
        #     requestInfo = self.helpers.analyzeRequest(entry)
        #     url = requestInfo.getUrl()
        #     try:
        #         decodedUrl = self.helpers.urlDecode(str(url))
        #     except Exception as e:
        #         continue
        #     if self.fromScope and self.callbacks.isInScope(url):
        #         urllist.append(decodedUrl.replace(hostUrls[0],"/"))
        #     else:
        #         for url in hostUrls:
        #             if decodedUrl.startswith(str(url)):
        #                 urllist.append(decodedUrl.replace(hostUrls[0],"/"))
        print("hostUrls:")
        # print(hostUrls)
        t = threading.Thread(target=self.sendURLToHive, args=(hostUrls, detailed,))
        t.daemon = True
        t.start()

    def checkHostInHive(self, ip="", hostname=""):
        if not ip and not hostname:
            print("Need ip or hostname")
        elif not ip and hostname:
            ip = socket.gethostbyname(hostname)
        else:
            pass

    def sendReqRspToHive(self,nodeID, ReqRes):
        print("in sendReqRspToHive")
        # print(ReqRes)
        respData = ReqRes['response'][:40000] if len(ReqRes['response'])>40000 else ReqRes['response']
        data = [{"nodeId":nodeID,"request":ReqRes['request'],"response":respData}]
        aaa = json.dumps(data)
        # print(aaa)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        # conn = httplib.HTTPConnection("127.0.0.1:1337")
        # print(json.dumps(data))
        print("ready to send req/resp")
        conn.request("POST", "/api/project/{}/graph/nodes".format(self.activeProjectId), aaa, headers)
        response = conn.getresponse()
        # print(response.status)
        if response.status == 200:
            print("OK")
        else:
            print("Something wrong: {}".format(response.status_code))
        return

    def addHostToHive(self,ip="", hostname="", port=""):
        print("in addHostToHive")
        if not ip and not hostname:
            print("Need ip or hostname")
        elif not ip and hostname:
            print("Resolving IP...")
            ip = socket.gethostbyname(hostname)
        elif ip and not hostname:
            # print(ip,port)
            self.customImportToHive(columns= ["ip", "port"],data=["{ip}:{port}".format(ip,port)])
        elif ip and hostname:
            # print(ip, hostname,port)
            self.customImportToHive(columns=["ip","hostname", "port"], data="{}:{}:{}".format(ip,hostname, port))

    def customImportToHive(self, columns, data,columnSep=":",rowSep="\\\\n"):
        print ("in customImportToHive")
        # self.ServerURL = "127.0.0.1:1337"
        if not self.activeProjectId or not self.ServerURL:
            print("Error! Need to know project name and ServerURL !")
            return
        data = '{{"columnSep":"{}","columns":{},"data":"{}","excludeHeaders":false,"rowSep":"{}"}}'.format(columnSep,json.dumps(columns),data,rowSep)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("POST", "/api/project/{}/graph/custom/parse".format(self.activeProjectId), data, headers)
        response = conn.getresponse()
        responseStatus = response.status
        respData = response.read()
        # print(responseStatus,respData)
        if responseStatus == 200:
            print("OK: {}".format(respData))
            data2 = '{{"rows":{}}}'.format(respData)
            conn.request("POST", "/api/project/{}/graph/custom/direct".format(self.activeProjectId), data2, headers)
            response = conn.getresponse()
            responseStatus = response.status
            respData = response.read()
            if responseStatus == 200:
                print("OK: {}".format(json.dumps(respData)))
            else:
                print("Something wrong: {}".format(responseStatus))
        else:
            print("Something wrong: {}".format(responseStatus))

    def sendURLToHive(self, urllist, detailed = False):
        print("in sendURLToHive")
        print(urllist)
        data = []
        for url in urllist:
            if urllist[url]["hostname"] + " application" in self.appsList.keys():
                print("App {} exists".format(urllist[url]["hostname"]))
                self.activeApptId = self.appsList[urllist[url]["hostname"]+" application"]["appID"]
                pass
            else:
                appID = self.checkAppExists(ip=urllist[url]["ip"], hostname=urllist[url]["hostname"],port=urllist[url]["port"])
            # print(appID)
                self.activeApptId = appID
        for uri in urllist.keys():
            data.append({"uri": uri})
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        # conn = httplib.HTTPConnection("127.0.0.1:1337")
        print("Sending URLs")
        conn.request("POST", "/api/project/{}/graph/apps/{}/uris".format(self.activeProjectId,self.activeApptId), json.dumps(data), headers)
        response = conn.getresponse()
        # print("Resp st={}".format(response.status))
        print("Req data = {}".format(json.dumps(data)))
        if response.status == 200:
            res = json.loads(response.read())
            print("Tst1")
            # print(res)
            for node in res:
                # print("Tst2")
                # print(node)
                # print("keys")
                # print(urllist.keys())
                # print(node["fullPath"])
                if node["fullPath"] in urllist.keys() and detailed:
                    print("Sending ReqResp...")
                    # print(urllist[node["fullPath"]])
                    # print(node)
                    self.sendReqRspToHive(node['id'], urllist[node["fullPath"]])
        else:
            print("Something wrong: {}".format(response.status_code))

    def getProjects(self):
        print("requesting Project list...")
        self.projectName.removeAllItems()
        # self.appName.removeAllItems()
        print(self.cookie)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/groups/", "" , headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = response.read()
            print("OK: {}".format(respBody))
            projects = json.loads(respBody)
            for prj in projects["projects"]:
                # print(prj["projectName"] + ":" + prj["projectId"])
                self.projectName.addItem(prj["projectName"] + "~" + prj["projectId"])
            for group in projects["children"]:
                groupname = group["name"]
                for prj in group["projects"]:
                    # print(f"[{groupname}] - {prj['projectName']}")
                    self.projectName.addItem("[" + groupname + "] - " + prj["projectName"]  + "~" + prj["projectId"])
        else:
            print("Something wrong: {}".format(response.status)) 

    def getProjectsNew(self):
        print("requesting Project list...")
        self.projectName.removeAllItems()
        self.appName.removeAllItems()
        print(self.cookie)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/groups/", "" , headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = response.read()
            print("OK: {}".format(respBody))
            projects = json.loads(respBody)
            for prj in projects:
                # print(prj["projectName"] + ":" + prj["projectId"])
                self.projectName.addItem(prj["projectName"] + "~" + prj["projectId"])
        else:
            print("Something wrong: {}".format(response.status))

    def setCookie(self, event):
        print ("Set cookie btn pressed!")
        self.cookie = self.CookieField.getText()
        print(self.cookie)
        # self.textCookieValue.setText(self.cookie)
        self.textCookieValue.setText("Cookie is set")
        # self.getProjects()

    def setServerURL(self, event):
        print("Set Server URL btn pressed!")
        self.ServerURL = self.ServerURLField.getText()
        print(self.ServerURL)
        self.textServerURL.setText(self.ServerURL)
        self.getProjects()

    def setProject (self, event):
        self.activeProjectId = self.projectName.getSelectedItem().split("~")[1]
        self.activeProjectName = self.projectName.getSelectedItem().split("~")[0]
        self.textProjectName.setText(self.activeProjectName)
        print ("selected prj value:\t"+self.activeProjectId)
        # print ("selected prj name:\t"+self.activeProjectName)
        # self.getApps()

    def getDataByID(self, nodeID):
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/project/{}/graph/nodes/{}".format(self.activeProjectId,nodeID),"" , headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = json.loads(response.read())
            return respBody
        return ""

    def setApp (self, event):
        self.activeApptId = self.appName.getSelectedItem().split("~")[1]
        self.activeAppName = self.appName.getSelectedItem().split("~")[0]
        self.textAppName.setText(self.activeAppName)
        print ("selected app id:\t"+str(self.activeApptId))

    def getAppList(self):
        print("requesting Application list...")
        # self.appName.removeAllItems()
        # print(self.appsList)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/project/{}/graph/apps".format(self.activeProjectId), "", headers)
        response = conn.getresponse()
        # self.appsList={}
        if response.status == 200:
            respBody = response.read()
            # print("OK: {}".format(respBody))
            apps = json.loads(respBody)
            if apps:
                for app in apps:
                    parentInfo = self.getDataByID(app["parentId"])
                    self.appsList[app["name"]]={"name":app["name"],
                                          "appID":app["id"],
                                          "ip":parentInfo["ip"],
                                          "hostname":app["hostnames"],
                                          "port":app["parentPort"]
                                          }
        # print(appsList)
        return self.appsList

    def sendAllIssuesToRepeater(self, event):
        print("sendAllIssuesToRepeater: btn pressed!")
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/project/{}/graph/issues".format(self.activeProjectId), "", headers)
        response = conn.getresponse()
        if response.status == 200:
            print("sendAllIssuesToRepeater: Got response")
            respBody = json.loads(response.read())
            if respBody:
                for items in respBody:
                    if items["requests"]:
                        for message in items["requests"]:
                            reallySentToRepeater = False
                            reqData     = message["request"]
                            # msgId       = message["id"]       # been using id as tab title, changed to handle
                            handle = reqData.split('\r\n')[0].split(' ')[1]
                            port = 443
                            useHttps = True
                            splitted_data = reqData.split('\n')
                            host = ''
                            for x in splitted_data:
                                if not host:
                                    if x.find('Host: ') != -1:
                                        host = x[x.find('Host: ')+6:].strip()
                                        break
                            # respData    = message["response"]  # And I thought we can paste response as well :shrug:
                            try:
                                self.callbacks.sendToRepeater(host, port, useHttps, reqData, handle)
                                print('sendAllIssuesToRepeater: Host \"'+host+'\" added')
                                reallySentToRepeater = True
                            except:
                                print("sendAllIssuesToRepeater: failed to add issue #"+str(msgId)+"; host was \'"+host+"\':"+str(port))
                                print(host.encode("hex"))
                            # if it failed to add port#443 + https, trying port#80+http
                            if not reallySentToRepeater:
                                port = 80
                                useHttps = False
                                try:
                                    self.callbacks.sendToRepeater(host, port, useHttps, reqData, handle)
                                except:
                                    print("sendAllIssuesToRepeater: failed to add issue #"+str(msgId)+"; host was \'"+host+"\':"+str(port))
                                    print(host.encode("hex"))
        else:
            print("sendAllIssuesToRepeater: failed to get issues from project")

    def createApp(self, ip, port, type="Pentest", hostname=""):
        print("in createApp")
        if hostname:
            appName = hostname + " application"
        else:
            appName = ip + " application"
        if not ip and not port:
            print("Need IP and port")
            return 0
        else:
            # res = self.doSearch("ip== "+ip + " and port == " + port)
            query = "ip == " +ip + " and port == " + str(port)
            print(query)
            res = self.doSearch(query)
            appParentID=res[0]["ports"][0]["id"]
            appHostID=0
            if hostname:
                # link hostname
                for seHostname in res[0]["hostnames"]:
                    if seHostname["hostname"] == hostname:
                        appHostID=seHostname["id"]
            if appParentID:
                data = [{"name":appName, "appType":type, "nodeId":appParentID}]
                headers = {"Content-Type": "application/json",
                           "Cookie": "BSESSIONID={}".format(self.cookie)
                           }
                conn = httplib.HTTPConnection(self.ServerURL)
                conn.request("POST", "/api/project/{}/graph/nodes".format(self.activeProjectId), json.dumps(data),
                             headers)
                response = conn.getresponse()
                if response.status == 200:
                    print("App " +appName +"  created")
                    resp = json.loads(response.read())
                    appID = resp[0]["id"]
                    # print(str(appID))
                    if appHostID:
                        # link hostname
                        data = [{"hostnameId":appHostID, "appId":appID}]
                        headers = {"Content-Type": "application/json",
                                   "Cookie": "BSESSIONID={}".format(self.cookie)
                                   }
                        conn = httplib.HTTPConnection(self.ServerURL)
                        conn.request("POST", "/api/project/{}/graph/relationships".format(self.activeProjectId),
                                     json.dumps(data),
                                     headers)
                        response = conn.getresponse()
                        if response.status == 200:
                            print("Linked hostname to App")
                        else:
                            print("can't link hostname to app")
                    return appID
                else:
                    print("Can't create app")
                    return 0

    def checkAppExists(self,hostname="", ip="",port=0):
        print("in checkAppExists")
        if not hostname and not ip:
            print("Need IP or hostname")
            return 0
        else:
            apps = self.getAppList()
            # print(ip)
            # print(apps)
            if apps:
                for app in apps:
                    if apps[app]["ip"] == ip and apps[app]["port"]==port:
                        print("App exists")
                        return apps[app]["appID"]
                    else:
                        print("Need to create app")
                        return self.createApp(ip,port, hostname=hostname)
            else:
                print("Need to create app")
                return self.createApp(ip, port, hostname=hostname)

    def getApps(self):
        print("requesting Application list...")
        self.appName.removeAllItems()
        print(self.cookie)
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/project/{}/graph/apps".format(self.activeProjectId), "", headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = response.read()
            print("OK: {}".format(respBody))
            apps = json.loads(respBody)
            for app in apps:
                self.appName.addItem(app["name"]+"~"+str(app["id"]))
        else:
            print("Something wrong: {}".format(response.status)) 
            
    def addPort(self, traffic):
        print("Adding  host, ip, port")
        # data={'rows':[{"hostname":traffic.host,"ip":socket.gethostbyname(traffic.host),"port":str(traffic.port),"service":traffic.protocol,"tag":"burp"}]}
        data={'rows':[{"hostname":traffic.host,"ip":socket.gethostbyname(traffic.host),"port":str(traffic.port),"service":traffic.protocol}]}
        # print("ready to post data:")
        # print(json.dumps(data))
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn2 = httplib.HTTPConnection(self.ServerURL)
        conn2.request("POST", "/api/project/{}/graph/custom".format(self.activeProjectId), json.dumps(data), headers)
        response = conn2.getresponse()
        if response.status == 200:
            # print("OK port posted: {}".format(json.dumps(data)))
            print("OK port posted")
        else:
            print("Something wrong: {}".format(response.status_code))
            
    def addSitemap(self, event):
        t3 = threading.Thread(target=self.addSitemapThread)
        t3.daemon = True
        t3.start()

    def addSitemapThread (self):
        print ("well well well...")
        
        headers = {"Content-Type": "application/json",
                   "Cookie": "BSESSIONID={}".format(self.cookie)
                   }
        conn = httplib.HTTPConnection(self.ServerURL)
        conn.request("GET", "/api/project/{}/graph/nodes/{}".format(self.activeProjectId,self.activeApptId),"" , headers)
        response = conn.getresponse()
        if response.status == 200:
            respBody = response.read()
            print("OK: {}".format(respBody))
            appinfo = json.loads(respBody)
            print("==================")
            print(appinfo)
            print("============----")
            #print (appinfo["hostnames"][0]["hostname"])
            app_hostname = str(appinfo["hostnames"][0]["hostname"])
            print (app_hostname)
            app_port = str(appinfo["parentPort"])
            print (app_port)
            for app_uri in appinfo["uris"]:
                print (str(app_uri["uri"]))
                
                app_schema = "https" if app_port == 443  else "http"                
                http_url = app_schema+"://"+app_hostname+":"+str(app_port)+str(app_uri["uri"])
                print(http_url)
                java_URL = URL(http_url)  
                                  
                port = java_URL.port if java_URL.port != -1 else port  
                httpService = self.helpers.buildHttpService(java_URL.host, port, java_URL.protocol)  
                httpRequest = self.helpers.buildHttpRequest(URL(http_url))  
                  
                self.callbacks.addToSiteMap(self.callbacks.makeHttpRequest(httpService, httpRequest))  
        print ("well done!")


    def workCreateIssueFromMessage(self):
        # Add info into issues
        print("In createIssueFromMessage")
        if not self.activeProjectId or not self.ServerURL:
            print("Error! Need to know project name and ServerURL !")
            return
        msg = self.context.getSelectedMessages()[0]
        req = msg.getRequest()
        resp = msg.getResponse()
        handle = b''.join([self.int_to_bytes(x) for x in req]).decode('utf-8').split('\r\n')[0].split(' ')[1]
        print("Handle is: " + handle)
        empty_issue_tamplate = [{
                "nodeId":None,
                "status":"new",
                "issueName":"issue created for path " + handle,
                "criticalityScore":None,
                "probabilityScore":None,
                "generalDescription":"",
                "recommendations":"",
                "reproduceDescription":"",
                "risksDescription":"",
                "technicalDescription":"",
                "weaknessType":"",
                "ips":[],
                "hostnames":[]
            }]
        print(json.dumps(empty_issue_tamplate)) 
        headers =   {
                        "Content-Type": "application/json",
                        "Cookie": "BSESSIONID={}".format(self.cookie)
                    }
        conn = httplib.HTTPConnection(self.ServerURL)
        print("workCreateIssueFromMessage: sending request to create issue")
        conn.request(
                        "POST",
                        "/api/project/{}/graph/nodes".format(self.activeProjectId),
                        json.dumps(empty_issue_tamplate),
                        headers
                    )
        response = conn.getresponse()
        responseStatus = response.status
        respData = response.read()
        if responseStatus == 200:
            print("workCreateIssueFromMessage: empty issue created")
            try:
                # nodeId - unique ID for created item in graph (issue, in our case)
                nodeId = json.loads(respData)[0]['id']
                req_data =   [{  
                            "request":b''.join([self.int_to_bytes(x) for x in req]).decode('utf-8'),
                            "response":b''.join([self.int_to_bytes(x) for x in resp]).decode('utf-8'),
                            "nodeId":nodeId
                        }]
                conn = httplib.HTTPConnection(self.ServerURL)
                conn.request(
                                "POST", 
                                "/api/project/{}/graph/nodes".format(self.activeProjectId), 
                                json.dumps(req_data),
                                headers
                            )
                response = conn.getresponse()
                responseStatus = response.status
                respData = response.read()
            except Exception as e:
                print("workCreateIssueFromMessage: caught some exception" + e)
            if responseStatus == 200:
                print("workCreateIssueFromMessage: issue from message has been created")
            else:
                print("Something wrong: {}".format(responseStatus))
        else:
            print("Something wrong: {}".format(responseStatus))

