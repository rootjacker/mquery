import logging

from itsdangerous import JSONWebSignatureSerializer
from redis import StrictRedis

import config


LOG_FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"
LOG_DATEFMT = "%d/%m/%Y %H:%M:%S"


def setup_logging():
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_DATEFMT)


def make_redis():
    return StrictRedis(host=config.REDIS_HOST, port=config.REDIS_PORT)


def make_serializer():
    return JSONWebSignatureSerializer(config.SECRET_KEY)


def convert_dict(d):
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in d.items()}


def convert_list(lst):
    return [x.decode('utf-8') for x in lst]
