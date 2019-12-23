#!/bin/bash
ps -ef | grep 'ryu-manager' | grep -v grep |awk '{print $2}' | xargs -r kill -9