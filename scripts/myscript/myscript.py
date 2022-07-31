import requests
from bs4 import BeautifulSoup
from eggdroppy import binds
from pprint import pprint
import eggdrop

def pubGetTitle(nick, user, hand, chan, text):
  print(text)
  reqs = requests.get(text)
  soup = BeautifulSoup(reqs.text, 'html.parser')
  eggdrop.putmsg(chan, "The title of the webpage is: "+soup.find_all('title')[0].get_text())

def pubmGetTitle(nick, user, hand, chan, text):
  print(text)
  reqs = requests.get(text.split()[1])
  soup = BeautifulSoup(reqs.text, 'html.parser')
  eggdrop.putmsg(chan, "The title of the webpage is: "+soup.find_all('title')[0].get_text())

def mypub(nick, user, hand, chan, text):
  eggdrop.putmsg(chan, "!!! "+nick+"+ on "+chan+" said "+text)
  return

def mypub2(nick, user, hand, chan, text):
  print("!!! "+nick+"+ on "+chan+" said "+text+" and is a global +o")
  return

#binds.add("pubm", "!moo", binds.FlagMatcher(), "*", mypub)
#binds.add("pubm", "!moo*", binds.FlagMatcher(globalflags=binds.UserFlags.o), "*", mypub2)
#binds.add("pub", "!title", binds.FlagMatcher(), "*", pubGetTitle)
#binds.add("pubm", "what*", binds.FlagMatcher(), "*", pubmGetTitle)
binds.join.add(joinGreetUser, binds.FlagMatcher(), "*")
binds.pubm.add(mypub, binds.FlagMatcher(), "*")
pprint(binds.list())
