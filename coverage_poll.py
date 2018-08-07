import redis
from time import sleep
from datetime import datetime, timedelta
from config import config
import json


def rollup(rclient, key, coverage):
    while True:
        cov = rclient.rpop(key)
        if cov is None:
            return coverage
        cov = json.loads(cov)
        if "b" in cov:
            bbs = cov["b"]
            for bb in bbs.keys():
                if bb not in coverage:
                    coverage[bb] = {"v": 0, "l": 0, "u": []}
                coverage[bb]["v"] += bbs[bb]["v"]
                coverage[bb]["l"] += bbs[bb]["l"]
                if cov["i"] not in coverage[bb]["u"]:
                    coverage[bb]["u"].append(cov["i"])


poll_interval = timedelta(minutes=1, seconds=30)
r = redis.StrictRedis(host=config['host'], port=config['port'], password=config['password'])
next_poll = datetime.now()
coverage = {}
while True:
    if datetime.now() > next_poll:
        print "Polling"
        next_poll = datetime.now() + poll_interval
        keys = r.keys(pattern="*_COVERAGE")
        for key in keys:
            k = key.split("_")[0]

            print "Retrieving Stored Results"
            cov = r.get("%s_STORE" % k)
            if cov is None:
                print "No Stored Results Found"
                cov = {}
            else:
                cov = json.loads(cov)

            print "Rolling Up: %s" % k
            cov = rollup(r, key, cov)
            print len(cov.keys())

            print "Storing Results"
            r.set(name="%s_STORE" % k, value=json.dumps(cov))

            print "Publish Results"
            for c in cov.keys():
                cov[c]["u"] = len(cov[c]["u"])
            data = {"c": "coverage", "u": "COV", "b": json.dumps(cov)}
            data = json.dumps(data, separators=(',', ':'), sort_keys=True)
            r.publish(k, data)
    else:
        print "Sleep"
        sleep(5)
