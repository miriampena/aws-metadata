#!/bin/bash
sudo ifconfig lo0 alias 169.254.169.254
sudo python metadata.py