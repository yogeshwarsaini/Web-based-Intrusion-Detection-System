
try:
    import os
    import tkinter.messagebox
    from os.path import exists
    import subprocess
    import psutil
    from tkinter import *
    from tkinter import ttk
    import tkinter.scrolledtext as scrolled_text
    from tkinter.messagebox import askyesno
    import os.path
    import firebase_admin
    from firebase_admin import db, credentials
    import re
    import requests
    import json
    import platform
except Exception as e:
   print("install required dependencies using 'depend.sh' file")




osname = platform.system()  

def chkdepend(os):
   if os == "Linux":
      if exists("installed.pnl"): 
         pass
      else:
         with open('installed.pnl' , 'wb') as f:
            f.write(('Information This is Intrusion Monitoring Panel\n\n'
                                    f'Made by Dhruv Sharma, Bhavyansh Pareek, Mayank Chawla\n\n'
                                    f'To know how to use application refer to readme.txt\n'
                                    
                                    f'For more information about how this works, please visit the GitHub page at '
                                    f'https://github.com/tritans472/Browser-Based-Intrusion-Prevention-System\n\n'
                                    f'this application is stored ').encode('utf-8'))
            f.close()
   else:
      print("some functionalities will not work on your os please use linux, debian is prefered")

chkdepend(osname)

url = 'https://www.virustotal.com/vtapi/v2/url/report'

majortreatflag = False

class IDS:

    def __init__(self, master):

        self.details = {
           'site':'',
           'clientip':'',
           'webname':'',
           'sitename':'',
           'statuscode':'',
           'virustotal':''
        }
        self.scanning = False
        self.grouped_output = None
        self.decision = 'wait'
        self.output = None
        self.stop_gui = None
        self.threatflag = False
        self.threatflagl2 = False
        self.link = 'https://github.com/tritans472/Browser-Based-Intrusion-Prevention-System'
        self.theme = 'light'
        self.p = psutil.Process()
        self.gui = master
        self.timer = 1
        ##==================================================================================================
        gui.geometry('700x530')
        master.title("Intrusion-Detection Panel")
## buttons 
        self.info_btn = ttk.Button(master, text="Info", command=self.show_info)
        self.info_btn.place(x=25,y=20)

        self.Arm = ttk.Label(master, text="Action")
        self.Arm.place(x=165, y=5)

        self.out_btn = ttk.Button(master, text="Start", command=self.start)
        self.out_btn.place(x=120, y=20)

        self.out_stp = ttk.Button(master, text="Stop", command=self.stop)
        self.out_stp.place(x=190, y=20)
        self.themebtn = ttk.Button(master, text="theme", command=self.toggleDarkMode)
        self.themebtn.place(x=550, y=20)

        self.add_startup = ttk.Label(master, text="|| Intrusion Detection System ||")
        self.add_startup.place(x=260, y=5)

        self.remove_startup = ttk.Label(master, text="Admin Control Panel")
        self.remove_startup.place(x=285, y=30)


        self.out_box = scrolled_text.ScrolledText(master, height=25, width=80)
        self.out_box.pack(padx=10, pady=15, expand=True)

        self.clear_chat = ttk.Button(master, text="Clear Panel", command=self.new_window)
        self.clear_chat.place(x=315, y=480)

        self.save_chat = ttk.Button(master, text="Save Logs", command=self.save_text)
        self.save_chat.place(x=135, y=480)


        self.see_blacklist = ttk.Button(master, text="Exit", command=self.exit)
        self.see_blacklist.place(x=510, y=480)


        gui.after(10)

    def new_window(self):
        self.out_box.delete('1.0', END)
        self.timer = 1
    
    ## main functions
    def show_info(self):
        tkinter.messagebox.showinfo("Information",
                                    f'This is Intrusion Monitoring Panel\n\n'
                                    f'Made by Dhruv Sharma, Bhavyansh Pareek, Mayank Chawla\n\n'
                                    f'To know how to use application refer to readme.txt\n'
                                    
                                    f'For more information about how this works, please visit the GitHub page at '
                                    f'{self.link}\n\n'
                                    f'this application is stored '
                                    f'at \n{os.getcwd()}.\n\n')

    def exit(self):
        print("Shutting down Services")
        self.stop()
        print("Exiting...")
        exit()



    def save_text(self):
        i = 1
        while exists("logs_%s.txt" % i):
            i += 1
        f = open('logs_%s.txt' % i, 'w')
        f.write(self.out_box.get('1.0', 'end-1c'))
        f.close()
        file_exists = exists(f'{os.getcwd()}/logs_%s.txt' % i)
        if file_exists:
            tkinter.messagebox.showinfo("Information", f'File saved successfully at {os.getcwd()}.')
        else:
            tkinter.messagebox.showerror("Error", "File was not created, please try again.")

        


    def start(self):
        self.scanning = True
        det = db.reference("/intrusion/detected").get()

        if self.timer == 1:
            self.out_box.insert(INSERT, "\nIDS in progress...\n")
            self.timer += 1

        if det:

            self.site = db.reference("/intrusion/site").get()
            self.clientip = db.reference("/intrusion/ip").get()
            self.details['site']=self.site
            self.details['clientip']=self.clientip
            self.out_box.insert(INSERT, "\n New Website Detected.\n")
            self.out_box.insert(INSERT, "Analysing Website...\n")

            if self.site != '':
                self.domain = fulldomain(self.site)  ## complete domain name using provided site
                self.webnm = websitename(self.site)
                self.whoisnm = whoischeck(self.domain)  ## complete dmn name using website scraping
                self.sitenm = justsitename(self.site) ## only site name using provided site
                self.statuscode = checkcode(self.site) ## error code checking using site
                self.virus = virustotal(self.domain)
                

                print('full domain:',self.domain)
                print('web name:',self.webnm)
                print('whois name:',self.whoisnm)
                print('site name:',self.sitenm)
                print('status code:',self.statuscode)
                print('malicious scan:',self.virus)


                if self.sitenm and self.webnm:
                    if self.sitenm not in self.webnm:
                        self.threatflag = True
                        self.details['webname']=self.webnm
                        self.details['whoisnm']=self.whoisnm
                        print("threat flag 1 up")
                
                if self.statuscode:
                    self.details['statuscode']=self.statuscode
                    print('threat flag 2 up')

                
                if self.virus:
                   if self.virus == 'malicious':
                      majortreatflag = True 
                   elif self.virus == 'safe':
                      majortreatflag= False
                   elif self.virus == 'not':
                      self.out_box.insert(INSERT, "\nVirustotal not responding...\n\n")
                      majortreatflag = True
                   else:
                      majortreatflag = False
                   self.details['virustotal']=self.virus
                   
                
                
                if majortreatflag or self.statuscode:
                   if self.statuscode:
                      self.alarmwithblacklist()
                   elif majortreatflag:
                      print("major threat detected")
                      self.alarmwithblacklist()
                   else:
                      self.alarmwithwhitelist()
                
                else:
                   self.alarmwithwhitelist()
                   print("threat not recognized")
                      
                      

        self.stop_gui = gui.after(10, self.start)
        self.out_box.see(END)


    def stop(self):
        if self.scanning == True:
            self.scanning = False
            db.reference("/intrusion/allow").set("wait")
            db.reference("/intrusion/detected").set(False)
            db.reference("/intrusion/site").set('')
            db.reference("/intrusion/ip").set('')
            self.out_box.insert(INSERT, "\nIDS stopped.\n\n")
            gui.after_cancel(self.stop_gui)
            self.timer = 1
            self.out_box.see(END)

    def toggleDarkMode(self):
        if self.theme == 'light':
            gui.tk.call("set_theme", "dark")
            self.theme = 'dark'

        else:
            gui.tk.call("set_theme", "light")
            self.theme = 'light'

    def alarmwithblacklist(self):
        
        self.out_box.insert(INSERT, 'Website name: {}\n'
                                    'Trying to communicate from {}\n'.format(self.details['site'], self.details['clientip']))
        self.out_box.insert(INSERT, "Making Decision\n")


        self.decision = 'denied'

        self.out_box.insert(INSERT, "Adding Site to Blacklist\n")

        db.reference("/intrusion/allow").set(self.decision)
        self.out_box.insert(INSERT, f"Decision : Access {self.decision} to {self.details['site']}\n")
        while self.decision not in ('wait'):
            gui.update()
            self.decision = db.reference('/intrusion/allow').get()
        self.out_box.insert(INSERT, "Site added to Blacklist\n")

        db.reference("/intrusion/detected").set(False)
        db.reference("/intrusion/site").set('')
        db.reference("/intrusion/ip").set('')
        self.timer=1

    def alarmwithwhitelist(self):
        
        self.out_box.insert(INSERT, 'Website name: {}\n'
                                    'Trying to communicate from {}\n'.format(self.details['site'], self.details['clientip']))
        self.out_box.insert(INSERT, "Making Decision\n")


        self.decision = 'granted'

        self.out_box.insert(INSERT, "Adding Site to Whitelist\n")

        db.reference("/intrusion/allow").set(self.decision)
        self.out_box.insert(INSERT, f"Decision : Access {self.decision} to {self.details['site']}\n")
        while self.decision not in ('wait'):
            gui.update()
            self.decision = db.reference('/intrusion/allow').get()
        self.out_box.insert(INSERT, "Site added to Whitelist\n")

        db.reference("/intrusion/detected").set(False)
        db.reference("/intrusion/site").set('')
        db.reference("/intrusion/ip").set('')
        self.timer=1

## validation functions

def maindomain(url): #supportive
  domain_pattern = r"^(?:https?://)?(?:[^\.]+\.)*([a-z0-9\-]{2,6})"
  match = re.match(domain_pattern, url, re.IGNORECASE) 

  if match:
    return match.group(1)
  else:
    return ['com']

def fulldomain(url):
   domain=''
   suffix = maindomain(url)
   a = url.find(suffix)
   i=a-1
   firstdot =1
   while i > 0:
      if url[i]=='.':
         if firstdot==2:
            i=0
         firstdot+=1
      if i!=0: 
        domain+=url[i]
      i-=1
    
   ## now the string is reversed
   reversed = domain[::-1]
   return reversed+suffix

def justsitename(url):
    domain=''
    suffix = maindomain(url)
    a = url.find(suffix)
    i=a-1
    firstdot =1
    while i > 0:
       if url[i]=='.':
          if firstdot==2:
             i=0
          firstdot+=1
       if i!=0: 
         domain+=url[i]
       i-=1
    reversed = domain[::-1]
    return reversed.replace('.','')

def websitename(url):
    if "www." not in url:
        url = "www."+url
    if ("https://" or "http://") not in url:
        url = "http://"+url
    print(url)
    a=''
    try:
        resp = requests.get(url)
        for i in range(len(resp.text)):
            a+=resp.text[i]
        matches = re.findall(r"<title>(.*?)</title>", a, re.DOTALL)
        return matches[0].lower()
    
    except Exception as e:
       return False

def whoischeck(url):
   
    print('this is domain name',url)
    try:
      webinfo = subprocess.check_output(["whois", url]).decode("utf-8")
      matches = re.findall(r"Domain Name:(.*?)\n", webinfo, re.DOTALL)
      return (matches[0].lower()).replace(' ','')
    except Exception as e:
      print(f"Error running whois: {e}")
      return False

# 305  - useproxy
# 306  - switch proxy
# 307   - temporary redirect
# 308   - permanent redirect
# 451   - unavailable for legal reasons
# 429   - too many requests
# 508   - loop detected

def checkcode(url):
  try:
    response = requests.get(url)
    # Check for 404 status code
    if response.status_code == 305:
      return response.status_code
    elif response.status_code == 306:
      return response.status_code
    elif response.status_code == 307:
      return response.status_code
    elif response.status_code == 308:
      return response.status_code
    elif response.status_code == 429:
      return response.status_code
    elif response.status_code == 451:
      return response.status_code
    elif response.status_code == 508:
      return response.status_code
    else:
      return False
  except requests.exceptions.RequestException as e:
    print(f"Error making request to {url}: {e}")
    return False  # Consider this an error as well

def virustotal(lnk):
    try:
        param = {'apikey':api, 'resource':lnk}
        response = requests.get(url,params = param)
        responseget = json.loads(response.content)
        # print(responseget)
        if responseget['positives']==0:
            return 'safe'
        elif responseget['positives']>=1:
            return 'malicious'
        else:
            return 'not'
    except Exception as e:
        return 'error'


   



# run program
if __name__ == "__main__":
    try:
      with open("fburl.txt", "r") as file_object:
        firebaseurl = file_object.readline().strip()
      cred = credentials.Certificate("browser.json")
      with open("vtapi.txt", "r") as file_object:
        api = file_object.readline().strip()
    except FileNotFoundError:
      print("authentication file not found. Username cannot be read.")
      exit()
    

    firebase_admin.initialize_app(cred, {"databaseURL": f"{firebaseurl}"})


    gui = Tk()
    run_app = IDS(gui)
    big_frame = ttk.Frame(gui)
    gui.tk.call("source", "theme/ids.tcl")
    gui.tk.call("set_theme", "light")
    # disable full-screen
    gui.resizable(False, False)
    # gui.iconbitmap('logo.ico')
    gui.mainloop()

