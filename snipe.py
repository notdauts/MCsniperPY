try:
    from os import path, system
    import aiohttp
    import logging
    from colorama import Fore, init
    from datetime import datetime, timezone
    import os
    import asyncio
    import time
    from bs4 import BeautifulSoup
    import sys
    import requests
except ImportError:
    print("Trying to install the required modules! Ignore the errors!\nPlease try to run this script again once all of the modules have been successfully installed.\n\n")
    input("Press enter to start installing... ")
    system("py -m pip install -r requirements.txt")
    system("python -m pip install -r requirements.txt")
    system("python3 -m pip install -r requirements.txt")
    input("\n\nSuccefully installed modules! please restart the script now. Press enter to continue... ")
    quit()

init()

logging.basicConfig(level=logging.INFO, format='%(message)s')
times = []
global sent_reqs
sent_reqs = 0
default_config = """timing_system:namemc
skin:PATH WITH FORWARD SLASHES (no quote marks)
skin_model:slim
change_skin:false
snipe_reqs:8
block_reqs:3
auth_delay:800
max_accs:30
auto_link_namemc:false NOT IMPLEMENTED
"""


def custom_info(message):
    logging.info(f"{Fore.WHITE}[{Fore.BLUE}info{Fore.WHITE}] {Fore.RESET}{message}")


def print_title():
    title = f"""
{Fore.MAGENTA}♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥
{Fore.CYAN}»{Fore.BLUE} nnnn  nnnnnnnn       ooooooooooo vvvvvvv           vvvvvvvuuuuuu    uuuuuu      ssssssssss
{Fore.CYAN}»{Fore.BLUE} n:::nn::::::::nn   oo:::::::::::oov:::::v         v:::::v u::::u    u::::u    ss::::::::::s
{Fore.CYAN}»{Fore.BLUE} n::::::::::::::nn o:::::::::::::::ov:::::v       v:::::v  u::::u    u::::u  ss:::::::::::::s
{Fore.CYAN}»{Fore.BLUE} nn:::::::::::::::no:::::ooooo:::::o v:::::v     v:::::v   u::::u    u::::u  s::::::ssss:::::s
{Fore.CYAN}»{Fore.BLUE}   n:::::nnnn:::::no::::o     o::::o  v:::::v   v:::::v    u::::u    u::::u   s:::::s  ssssss
{Fore.CYAN}»{Fore.BLUE}   n::::n    n::::no::::o     o::::o   v:::::v v:::::v     u::::u    u::::u     s::::::s
{Fore.CYAN}»{Fore.BLUE}   n::::n    n::::no::::o     o::::o    v:::::v:::::v      u::::u    u::::u        s::::::s
{Fore.CYAN}»{Fore.BLUE}   n::::n    n::::no::::o     o::::o     v:::::::::v       u:::::uuuu:::::u  ssssss   s:::::s
{Fore.CYAN}»{Fore.BLUE}   n::::n    n::::no:::::ooooo:::::o      v:::::::v        u:::::::::::::::uus:::::ssss::::::s
{Fore.CYAN}»{Fore.BLUE}   n::::n    n::::no:::::::::::::::o       v:::::v          u:::::::::::::::us::::::::::::::s
{Fore.CYAN}»{Fore.BLUE}   nnnnnn    nnnnnn   ooooooooooo            vvv               uuuuuuuu  uuuu  sssssssssss
{Fore.MAGENTA}♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥♥
{Fore.CYAN}» {Fore.BLUE}Created by dauts#3050
{Fore.CYAN}» {Fore.BLUE}github.com/notdauts"""
    print(title)


def custom_input(message):
    print(f"{Fore.GREEN}» {Fore.RESET}", end='')
    input_return = input(message)
    return input_return


def check_resp(status):
    if str(status)[0] == str(2):
        return True
    else:
        return False


def resp_error(message):
    print(f"{{Fore.GREEN}Success »{Fore.WHITE} {message}")


async def namemc_timing(target, block_snipe):
    now = datetime.utcnow()
    block_snipe_words = ["snipe", "block"]
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://namemc.com/search?q={target}", ssl=False) as page:
                # page = requests.get(namemc_url)
                soup = BeautifulSoup(await page.text(), 'html.parser')
                snipe_time = soup.find("time", {"id": "availability-time"}).attrs["datetime"]
                snipe_time = datetime.strptime(snipe_time, '%Y-%m-%dT%H:%M:%S.000Z')
        except AttributeError:
            status_bar = soup.find(id="status-bar")
            info = status_bar.find_all("div", class_="col-sm-6 my-1")
            status = info[0].text.split("\n")[2]
            if status.lower().rstrip('*') == 'available':
                custom_info(f"\"{target}\" is {status}. The sniper can turbo {status} names!")
                snipe_time = custom_input("At what time will this name be able to be turboed (month/day/yr, 24hrtime_hour:minute:second) (UTC)\nexample: 03/06/2020 01:06:45\n» ")
                try:
                    snipe_time = datetime.strptime(snipe_time.strip(), "%m/%d/%Y %H:%M:%S")
                except ValueError:
                    resp_error("invalid time format")
                    raise ValueError
                wait_time = snipe_time - now
                wait_time = wait_time.total_seconds()
                if wait_time >= 60:
                    custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in ~{round(wait_time / 60)} minutes | {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
                else:
                    custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in {wait_time} seconds | {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
                custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in {wait_time} minutes | {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
                return int(snipe_time.replace(tzinfo=timezone.utc).timestamp())
            print(f"\"{target}\" is {status}. The sniper cannot claim names that are {status} so go claim it fast through https://my.minecraft.net if possible.")
            quit()

        wait_time = snipe_time - now
        wait_time = wait_time.total_seconds()
        if wait_time >= 60:
            custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in ~{round(wait_time / 60)} min. | {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
        elif wait_time >= 3600:
            custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in ~{round(wait_time / 3600)} min.| {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
        else:
            custom_info(f"{block_snipe_words[block_snipe].rstrip('e')}ing \"{target}\" in {wait_time} sec. | {block_snipe_words[block_snipe].rstrip('e')}ing at {snipe_time} (utc)")
        return int(snipe_time.replace(tzinfo=timezone.utc).timestamp())


async def time_snipe(target, block_snipe):
    try:
        return await namemc_timing(target, block_snipe)
    except Exception:
        print(f"{Fore.RED}Error »{Fore.WHITE} Failed to time snipe")
        time.sleep(3)
        quit()


class Config:
    def __init__(self):
        self.options = []
        if not os.path.exists("config.txt"):
            with open("config.txt", "w") as f:
                f.write(default_config)
        with open("config.txt", "r") as f:
            unconverted_lines = f.readlines()
            self.lines = list()
            for line in unconverted_lines:
                self.lines.append(line.strip())
            self.timing = self.find_parameter("timing_system")
            self.block_reqs = int(self.find_parameter("block_reqs"))
            self.snipe_reqs = int(self.find_parameter("snipe_reqs"))
            self.skin = self.find_parameter("skin")
            self.max_accs = int(self.find_parameter("max_accs"))
            if "namemc.com/skin" in self.skin:
                self.skin = f"https://namemc.com/texture/{self.skin.split('/')[-1]}.png"
            self.custom_announce = self.find_parameter("custom_announce")
            if self.custom_announce is None:
                del self.custom_announce
            self.change_skin = self.find_bool("change_skin", False)
            self.auth_delay = int(self.find_parameter("auth_delay"))
            self.webhooks = self.find_all("wh")
            self.skin_model = self.find_parameter("skin_model")

    def find_parameter(self, parameter):
        for line in self.lines:
            line = line.split(":")
            if line[0].lower() == parameter:
                line.pop(0)
                line = ":".join(line)
                self.options.append(line)
                return line

    def find_bool(self, parameter, default):
        parameter = self.find_parameter(parameter)
        parameter = {"false": False, "true": True}[parameter]
        return parameter

    def find_all(self, parameter):
        options = []
        for line in self.lines:
            line = line.split(":")
            if line[0] == parameter:
                line.pop(0)
                options.append(":".join(line))
                self.options.append(options)
        return options


class Account:
    def __init__(self, email, password, questions=[]):
        self.email = email
        self.password = password
        self.questions = questions
        self.got_name = False
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"
        self.failed_auth = False
        self.authenticate_json = {"username": self.email, "password": self.password}
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0", "Content-Type": "application/json"}

    async def authenticate(self, session, sleep_time, block_snipe):
        await asyncio.sleep(sleep_time)
        # custom_info(f"{Fore.WHITE}starting auth for {self.email}")
        debug_mode = False
        async with session.post("https://authserver.mojang.com/authenticate", json=self.authenticate_json, headers=self.headers) as r:
            if check_resp(r.status):
                resp_json = await r.json()
                try:
                    self.uuid = resp_json["selectedProfile"]["id"]
                except KeyError:
                    if debug_mode:
                        print(resp_json)
                    else:
                        if block_snipe == 2:
                            custom_info(f"{self.email} is not paid and unable to snipe. {Fore.RED}Sniping like this will fail.{Fore.RESET}")
                self.auth = {"Authorization": "Bearer: " + resp_json["accessToken"]}
                self.access_token = resp_json["accessToken"]
            else:
                resp_error(f"invalid credentials | {self.email}")
                self.failed_auth = True
                return
        async with session.get("https://api.mojang.com/user/security/challenges", headers=self.auth) as r:
            answers = []
            if check_resp(r.status):
                resp_json = await r.json()
                if resp_json == []:
                    async with session.get("https://api.minecraftservices.com/minecraft/profile/namechange", headers={"Authorization": "Bearer " + self.access_token}) as ncE:
                        ncjson = await ncE.json()
                        try:
                            if ncjson['nameChangeAllowed'] is False:
                                logging.info(f"{Fore.RED}Error »{Fore.WHITE} {self.email} is not able to change username.")
                                self.failed_auth = True
                            else:
                                logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} Logged into {self.email}")
                        except Exception:
                            logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} Logged into {self.email} successfully!")
                else:
                    try:
                        for x in range(3):
                            answers.append({"id": resp_json[x]["answer"]["id"], "answer": self.questions[x]})
                    except IndexError:
                        logging.info(f"{Fore.RED}Error »{Fore.WHITE} {self.email} has security questions, but none were provided.")
                        self.failed_auth = True
                        return
                    async with session.post("https://api.mojang.com/user/security/location", json=answers, headers=self.auth) as r:
                        if check_resp(r.status):
                            logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} signed in to {self.email}{Fore.RESET}")
                        else:
                            resp_error(f"security questions incorrect | {self.email}")
                            self.failed_auth = True
            else:
                logging.info(f"{Fore.RED}Error »{Fore.WHITE} Authentication failed with the account under{self.email} {Fore.RED} STATUS {r.status}")
                self.failed_auth = True

    async def snipe_req(self, session, target_username):
        await asyncio.sleep(0)
        try:
            async with session.put(f"https://api.minecraftservices.com/minecraft/profile/name/{target_username}", headers={"Authorization": "Bearer " + self.access_token, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0", "Content-Type": "application/json"}) as response:
                now = datetime.now()
                global sent_reqs
                sent_reqs += 1
                await response.read()
                if response.status == 204 or response.status == 200:
                    logging.info(f"{Fore.GREEN}●{Fore.WHITE}» {Fore.BLUE} Sniped {Fore.MAGENTA}{target_username}{Fore.WHITE} via {self.email} ○ {Fore.GREEN}{response.status}{Fore.WHITE} @ {Fore.CYAN}{now}{Fore.RESET}")
                    self.got_name = True
                    if config.change_skin:
                        await self.authenticate(session, 1, 1)
                    asyncio.get_event_loop().stop()
                else:
                    logging.info(f"{Fore.RED}●{Fore.WHITE}» {Fore.BLUE}{response.status} {Fore.WHITE}@{Fore.CYAN} {now}{Fore.RESET}")
        except AttributeError as e:
            print(f'{Fore.RED}●{Fore.WHITE}»{Fore.RESET} Account {self.email} could not authenticate! {e}')

    def webhook_skin_write_file(self, block_snipe):
        time.sleep(1)
        with requests.session() as session:
            with open("success.txt", "a") as f:
                f.write(f"{self.email}:{self.password} - {target_username}\n")
            if config.change_skin:
                payload = {"variant": str(config.skin_model)}
                files = [('file', open(str(config.skin), 'rb'))]
                with session.post(f"https://api.minecraftservices.com/minecraft/profile/skins", headers=self.auth, data=payload, files=files) as r:
                    if r.status_code == 204 or r.status_code == 200:
                        logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} Changed skin model for {self.email}")
                    else:
                        logging.info(f"{Fore.WHITE}[{Fore.RED}FAIL{Fore.WHITE}]{Fore.RESET} Failed to change skin {self.email} | {str(r.status_code)}")
                        logging.info(r.json())
            else:
                custom_info(f"not changing skin | {self.email}")
            for hook in config.webhooks:
                searches = requests.get(f"https://api.nathan.cx/searches/{target_username}").json()["searches"]
                with session.post(hook, json={"embeds": [{"title": "Snipe Completed", "description": f"Sniped `{target_username}` with {searches} searches using Novus", "color": 65395}]}) as r:
                    if r.status_code == 200 or r.status_code == 204:
                        logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} Webhook was sent successfully")
                    else:
                        logging.info(r.status_code_code)
                        logging.info(r.json())
            if len(config.webhooks) == 0:
                custom_info("No webhooks were detected. Please put a webhook into the config.txt with \"wh:\" before it")
            try:
                with session.post("https://announcements-api.herokuapp.com/api/v1/announce", json={"name": target_username.strip()}, headers={"Authorization": config.custom_announce}) as r:
                    if r.status_code == 204:
                        logging.info(f"{Fore.GREEN}Success »{Fore.WHITE} sent custom announcement of snipe!")
                    else:
                        logging.info(f"{Fore.RED} {r.status_code} | Failed to send custom announcement!{Fore.RESET}")
                        print(r.json())
            except AttributeError as e:
                custom_info(f"Unable to announce snipe {e}")
                custom_info("Discord webhook is unavalbile")


def gather_info():
    block_snipe = 0
    target_username = custom_input(f"{['Snipe Account', 'Block Account'][block_snipe]}: ")
    try:
        delay = int(custom_input("Delay: "))
    except ValueError:
        print('Invalid Number')
    return block_snipe, target_username, delay


def load_accounts_file():
    accounts = []
    if not path.exists("accounts.txt"):
        print(f"{Fore.RED}Setup »{Fore.WHITE} Could not fine accounts.txt | Creating file...")
        open('accounts.txt', 'w+')
        input("Press enter to reload accounts.txt ")
        load_accounts_file()
    else:
        accounts = open('accounts.txt').readlines()
        if len(accounts) == 0:
            print(f"{Fore.RED}Setup »{Fore.WHITE} Please add account details to the accounts.txt file! Format: (email:pass) or (email:pass:q1:q2:q3)")
            input("Press any key to reload the accounts file")
            load_accounts_file()
        if len(accounts) > config.max_accs:
            print(f"{Fore.YELLOW}Warn {Fore.CYAN}»{Fore.WHITE} You have too many accounts! Removing {len(accounts) - config.max_accs}...")
            accounts = accounts[0:30]
    return accounts


def load_accounts():
    accounts = []
    for acc in load_accounts_file():
        acc = acc.rstrip().split(":")
        if acc == ['']:
            continue
        try:
            accounts.append(Account(acc[0], acc[1], [acc[2], acc[3], acc[4]]))
        except IndexError:
            accounts.append(Account(acc[0], acc[1]))
    return accounts


class session:
    block_snipe = ["Snipe", "block"]

    def __init__(self, target_username, accounts, block_snipe, snipe_delay):
        self.target_username = target_username
        self.accounts = accounts
        self.block_snipe = block_snipe
        self.snipe_delay = snipe_delay
        loop = asyncio.get_event_loop()
        self.drop_time = loop.run_until_complete(time_snipe(self.target_username, self.block_snipe))
        try:
            self.setup_time = self.drop_time - 55
        except Exception:
            resp_error(f"{Fore.RED}Error »{Fore.WHITE}Unable to snipe {target_username}")
            time.sleep(2)
            quit()
        self.setup = False
        self.ran = False
        self.drop_time = self.drop_time - snipe_delay / 1000

    def run(self):
        loop = asyncio.get_event_loop()
        while True:
            now = time.time()
            if now >= self.drop_time and not self.ran:
                try:
                    start = time.time()
                    loop.run_until_complete(self.send_requests())
                except RuntimeError:
                    pass
                end = time.time()
                elapsed_time = end - start
                for acc in self.accounts:
                    if acc.got_name:
                        time.sleep(2)
                        acc.webhook_skin_write_file(self.block_snipe)
                rq_sec = sent_reqs / elapsed_time
                times.append(rq_sec)
                logging.info(f"{Fore.BLUE}Results {Fore.CYAN}»{Fore.WHITE} {str(sum(times))[0:13]}{Fore.CYAN} rqs/sec (ESTIMATE) {Fore.WHITE}|{Fore.CYAN} Took {Fore.WHITE}{str(elapsed_time)[0:8]}{Fore.CYAN} seconds{Fore.RESET} | {sent_reqs} requests")
                try:
                    if len(sys.argv) < 3:
                        custom_input("press enter to quit: ")
                    return
                except Exception:
                    return
            elif now >= self.setup_time and not self.setup:
                loop.run_until_complete(self.run_auth())
                for acc in accounts:
                    if acc.failed_auth:
                        logging.info(f"{Fore.RED}Error »{Fore.WHITE} Removing account: {acc.email} | auth failed")
                        accounts.remove(acc)
                if len(accounts) == 0:
                    logging.info(f"{Fore.RED}Error »{Fore.WHITE} You don't have any working accounts. stopping program...")
                    quit()
                custom_info("{Fore.GREEN}Success »{Fore.WHITE}Setup finished")
                self.setup = True
            time.sleep(.00001)

    async def webhook_skin_file(self, acc):
        await acc.webhook_skin_write_file()

    async def send_requests(self):
        async with aiohttp.ClientSession() as session:
            if self.block_snipe == 0:
                self.coros = [
                    acc.snipe_req(session, self.target_username) for acc in self.accounts for _ in range(config.snipe_reqs)
                ]
            elif self.block_snipe == 1:
                self.coros = [
                    acc.block_req(session, self.target_username) for acc in self.accounts for _ in range(config.block_reqs)
                ]
            await asyncio.wait(self.coros)

    async def run_auth(self):
        async with aiohttp.ClientSession() as session:
            coros = [
                acc.authenticate(session, self.accounts.index(acc) * (config.auth_delay / 1000), self.block_snipe) for acc in self.accounts
            ]
            await asyncio.wait(coros)


if __name__ == '__main__':
    print_title()
    config = Config()
    accounts = load_accounts()
    try:
        target_username = sys.argv[1]
        block_snipe = sys.argv[2]
        if str(block_snipe).lower() == "snipe" or str(block_snipe) == "0":
            block_snipe = 0
        if str(block_snipe).lower() == "block" or str(block_snipe) == "1":
            block_snipe = 1
        try:
            snipe_delay = int(sys.argv[3])
        except IndexError:
            if block_snipe == 0:
                snipe_delay = 900
            else:
                snipe_delay = 200
    except IndexError:
        block_snipe, target_username, snipe_delay = gather_info()
    session = session(target_username, accounts, block_snipe, snipe_delay)
    session.run()
