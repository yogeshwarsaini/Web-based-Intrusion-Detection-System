import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTabWidget, QWidget, QShortcut, QLabel, QComboBox
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QIcon
from PyQt5.QtWebEngineWidgets import QWebEngineSettings
from PyQt5.QtNetwork import QNetworkProxy
import firebase_admin
from firebase_admin import db, credentials
import requests
import os

try:
  with open("fburl.txt", "r") as file_object:
    firebaseurl = file_object.readline().strip()
except FileNotFoundError:
  print("usr.txt file not found. Username cannot be read.")

cred = credentials.Certificate("browser.json")
firebase_admin.initialize_app(cred, {"databaseURL": f"{firebaseurl}"})

whlst = db.reference('/intrusion/whitelist')
blklst = db.reference('/intrusion/blacklist')


def get_my_ip():
    url = "https://api.ipify.org" 
    response = requests.get(url)
    if response.status_code == 200:
      return response.text.strip()
    else:
      print("Error getting global IP:", response.status_code)
      return None


engine = 0
zoom = 1.00
anonymous = False
blacklist = blklst.get()
whitelist = whlst.get()


print("blacklist:",blacklist)
print("whitelist:",whitelist)

class WebBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.dark_mode = False
        self.initUI()
        self.closed_tabs = []
        self.tabcount = 0

    ## ===================================UI management=======================================
    def initUI(self):
        self.setWindowTitle("Hidden")
        self.setWindowIcon(QIcon('hidden_logo.png')) 

        self.tabs = QTabWidget()
        self.go_button = QPushButton('Go')
        self.url_input = QLineEdit()  ## search bar
        self.new_tab_button = QPushButton('New Tab')
        self.close_tab_button = QPushButton('Close Tab')
        self.reload_button = QPushButton('Reload')
        self.back_button = QPushButton('Back')
        self.ctrl = QPushButton('Control')
        # self.serverbtn = QPushButton('Server')
        self.connectindicator = QLabel('Search Status: Public')
        self.dark_mode_button = QPushButton('Dark Mode')

        self.go_button.clicked.connect(self.loadURL)
        self.new_tab_button.clicked.connect(self.addNewTab)
        self.close_tab_button.clicked.connect(self.closeCurrentTab)
        self.reload_button.clicked.connect(self.reloadPage)
        self.back_button.clicked.connect(self.goBack)
        self.ctrl.clicked.connect(self.ctrlpnl)
        # self.serverbtn.clicked.connect(self.servercd)
        self.dark_mode_button.clicked.connect(self.toggleDarkMode)

        address_bar_layout = QHBoxLayout()
        address_bar_layout.addWidget(self.go_button)
        address_bar_layout.addWidget(self.new_tab_button)
        address_bar_layout.addWidget(self.close_tab_button)
        address_bar_layout.addWidget(self.reload_button)
        address_bar_layout.addWidget(self.back_button)
        address_bar_layout.addWidget(self.url_input)  ## search bar
        address_bar_layout.addWidget(self.ctrl)
        # address_bar_layout.addWidget(self.serverbtn)
        address_bar_layout.addWidget(self.dark_mode_button)

        ## layout management here  =========================================================
        layout = QVBoxLayout()
        layout.addLayout(address_bar_layout)
        layout.addWidget(self.connectindicator)  ### connect indicator indicator
        layout.addWidget(self.tabs)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.setGeometry(100, 100, 1800, 1200)

        self.addNewTab()

        ## shortcuts from here =========================================================
        new_tab_shortcut = QShortcut(Qt.CTRL + Qt.Key_T, self)
        new_tab_shortcut.activated.connect(self.addNewTab)

        close_tab_shortcut = QShortcut(Qt.CTRL + Qt.Key_W, self)
        close_tab_shortcut.activated.connect(self.closeCurrentTab)

        # servercon_shortcut = QShortcut(Qt.CTRL + Qt.Key_C, self)
        # servercon_shortcut.activated.connect(self.servercd)

        enter_shortcut = QShortcut(Qt.Key_Enter, self)
        enter_shortcut.activated.connect(self.loadURL)

        return_shortcut_shortcut = QShortcut(Qt.Key_Return, self)
        return_shortcut_shortcut.activated.connect(self.loadURL)

        reload_shortcut = QShortcut(Qt.CTRL + Qt.Key_R, self)
        reload_shortcut.activated.connect(self.reloadPage)

        back_shortcut = QShortcut(Qt.AltModifier + Qt.LeftArrow, self)
        back_shortcut.activated.connect(self.goBack)

        forward_shortcut = QShortcut(Qt.AltModifier + Qt.RightArrow, self)
        forward_shortcut.activated.connect(self.goForward)

        control_shortcut = QShortcut(Qt.AltModifier + Qt.Key_H, self)
        control_shortcut.activated.connect(self.ctrlpnl)

        closeCurrentwindow = QShortcut(Qt.CTRL + Qt.SHIFT + Qt.Key_W, self)
        closeCurrentwindow.activated.connect(self.exitfunc)

        reopen_closed_tab_shortcut = QShortcut(Qt.CTRL + Qt.SHIFT + Qt.Key_T, self)
        reopen_closed_tab_shortcut.activated.connect(self.reopenClosedTab)

        # dropdown box
        self.dropdown = QComboBox()
        self.dropdown.addItem("DuckDuckGo")
        self.dropdown.addItem("Google")
        self.dropdown.addItem("Bing")
        self.dropdown.currentIndexChanged.connect(self.handleDropdownSelection)

        # added dropdown
        address_bar_layout.addWidget(self.dropdown)

    ### =================================layout management end here===============================

    ## = ================================function here ===========================================
    def toggleDarkMode(self):
        self.dark_mode = not self.dark_mode  # dark mode status

        if self.dark_mode:
            self.setStyleSheet("background-color: #333333; color: #32CD32;")  # Dark theme

        else:
            self.setStyleSheet("")  # light theme

    def handleDropdownSelection(self):
        global engine
        selected_option = self.dropdown.currentText()

        if selected_option == "DuckDuckGo":
            print("search engine = DuckDuckGo")
            engine = 0
        elif selected_option == "Google":
            print("search engine = Google")
            engine = 1
        elif selected_option == "Bing":
            print("search engine = bing")
            engine = 2
        else:
            engine = 0
            print('error usve23x3 - cannot load engine')
        WebBrowser.addNewTab(self)

    def exitfunc(self):
        sys.exit(app.exec_())

    def reopenClosedTab(self):
        if self.closed_tabs:
            # Pop the last closed tab from the list
            last_closed_tab_url = self.closed_tabs.pop()

            # Create a new tab with the URL of the last closed tab
            web_view = QWebEngineView()
            web_view.load(QUrl(last_closed_tab_url))
            web_view.titleChanged.connect(lambda title: self.tabs.setTabText(self.tabs.indexOf(web_view), title))
            self.tabs.addTab(web_view, 'Loading...')  # Use a placeholder until the title is fetched
            self.tabs.setCurrentWidget(web_view)
            self.tabs.currentWidget().setZoomFactor(zoom)

    def addNewTab(self):
        global engine
        if engine == 0:
            url = 'duckduckgo.com'
        elif engine == 1:
            url = 'google.com'
        elif engine == 2:
            url = 'bing.com'
        web_view = QWebEngineView()
        web_view.load(QUrl(f'http://{url}'))
        web_view.titleChanged.connect(lambda title: self.tabs.setTabText(self.tabs.indexOf(web_view), title))
        self.tabs.addTab(web_view, 'Loading...')  # Use a placeholder until the title is fetched
        self.tabs.setCurrentWidget(web_view)
        self.tabs.currentWidget().setZoomFactor(zoom)
        
    def closeCurrentTab(self):
        if self.tabs.count() > 1:
            current_index = self.tabs.currentIndex()
            current_url = self.tabs.currentWidget().url().toString()
            self.closed_tabs.append(current_url)  # Save the closed tab's URL
            self.tabs.removeTab(current_index)
        else:
            print("operations ended")
            exit()

    def reloadPage(self):
        self.tabs.currentWidget().reload()
        self.tabs.currentWidget().setZoomFactor(zoom)

    def goBack(self):
        self.tabs.currentWidget().back()
        self.tabs.currentWidget().setZoomFactor(zoom)

    def goForward(self):
        current_web_view = self.tabs.currentWidget()
        if current_web_view and current_web_view.history().canGoForward():
            current_web_view.forward()

    def ctrlpnl(self):
        self.tabs.currentWidget().setUrl(QUrl('http://localhost:5000'))
        self.tabs.currentWidget().setZoomFactor(zoom)
        self.tabs.currentWidget().setZoomFactor(zoom)

    def setZoomFactor(self, factor):
        current_web_view = self.tabs.currentWidget()
        if current_web_view:
            current_web_view.setZoomFactor(factor)



    ##=================== functions under debug ===================================================================
    def loadURL(self):
        url = self.url_input.text()
        print('\n \nthis is the url: ', url + '\n \n')
        if 'http://' or 'https://' not in url:
            if "www." not in url:
                url = "https://www."+url
            else:
                url = "https://"+url

        blocked = f"{os.getcwd()}\\blocked.html"
        is_blacklisted = any(item in url for item in blacklist)  # Check for blacklist match
        is_whitelisted = any(item in url for item in whitelist)

        if is_blacklisted:
            with open(blocked, 'r') as f:
                blockedurl = f.read()
            self.tabs.currentWidget().setHtml(blockedurl)
        elif is_whitelisted:
            self.loadsite(url)
        else:
            with open(blocked, 'r') as f:
                blockedurl = f.read()
            self.tabs.currentWidget().setHtml(blockedurl)
            print("Blacklisted URL detected, loading Blocked HTML")
            self.updateonbase(url)
            decision = db.reference('/intrusion/allow').get()
            while decision not in ('granted', 'denied'):
                browser.update()  # Update the GUI to process button clicks
                decision = db.reference('/intrusion/allow').get()
            if decision == 'granted':
                self.loadsite(url)
                whitelist.append(url)
                whlst.set(whitelist)
                db.reference('/intrusion/allow').set("wait")
                db.reference('/intrusion/ip').set('')
            elif decision == 'denied':
                self.tabs.currentWidget().setHtml(blockedurl)
                blacklist.append(url)
                blklst.set(blacklist)
                db.reference('/intrusion/allow').set("wait")
                db.reference('/intrusion/ip').set('')
                


###===================================================================================
    def loadsite(self, url):
    # Load the original URL if not blacklisted
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        proxy = QNetworkProxy()
        proxy.setType(QNetworkProxy.HttpProxy)
        proxy.setHostName('192.168.146.80')  # Server address
        proxy.setPort(6378)  # Port
        if anonymous == True:
            QNetworkProxy.setApplicationProxy(proxy)
            print('private')
        else:
            deproxy = QNetworkProxy()
            QNetworkProxy.setApplicationProxy(deproxy)
            print('public')
        # Youtube fullscreen
        if 'youtube.com' in url:
            self.tabs.currentWidget().settings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        self.tabs.currentWidget().setUrl(QUrl(url)) 
        self.tabs.currentWidget().setZoomFactor(zoom)   

    def updateonbase(self, data):
        my_ip = get_my_ip()
        db.reference('/intrusion/ip').set(my_ip)
        ref = db.reference("/intrusion/detected")
        ref.set(True)
        print(db.reference("/intrusion/detected").get())
        db.reference("/intrusion/site").set(data)
        print(db.reference("/intrusion/site").get())
        return

            
        
            
            
## ================================= functions ends here ======================================

if __name__ == '__main__':
    
    try:
        app = QApplication(sys.argv)
        browser = WebBrowser()
        browser.show()
        sys.exit(app.exec_())

    except KeyboardInterrupt:
        print("Browser closed")
