#!/usr/bin/env python
import json
import logging
import time

import yara
import plyara
from yara import SyntaxError

import config
from lib.ursadb import UrsaDb
from lib.yaraparse import YaraParser
from util import make_redis, setup_logging, convert_dict

redis = make_redis()
db = UrsaDb(config.BACKEND)


def job_daemon():
    setup_logging()
    logging.info('Daemon running...')

    while True:
        queue, data = redis.blpop(['jobs', 'index-jobs', 'metadata-jobs'])

        if queue == b'jobs':
            query_hash = data
            logging.info('New task: {}:{}'.format(queue, query_hash))
            job_id = 'job:' + query_hash.decode('utf-8')

            try:
                execute_job(job_id, query_hash.decode('utf-8'))
            except Exception as e:
                logging.exception('Failed to execute job.')
                redis.hmset(job_id, {
                    'status': 'failed',
                    'error': str(e),
                })
        elif queue == b'index-jobs':
            path = data
            db.index(path)
        elif queue == b'metadata-jobs':
            query_hash, file_path = data.decode('utf-8').split(':', 1)
            resolve_metadata(query_hash, file_path)


def resolve_metadata(query_hash, file_path):
    current_meta = {}

    for extractor in config.METADATA_EXTRACTORS:
        extr_name = extractor.__class__.__name__
        local_meta = {}
        deps = extractor.__depends_on__

        for dep in deps:
            if dep not in current_meta:
                raise RuntimeError('Configuration problem {} depends on {} but is declared earlier in config.'
                                   .format(extr_name, dep))

            # we build local dictionary for each extractor, thus enforcing dependencies to be declared correctly
            local_meta.update(current_meta[dep])

        current_meta[extr_name] = extractor.extract(file_path, local_meta)

    # flatten
    flat_meta = {}

    for v in current_meta.values():
        flat_meta.update(v)

    redis.sadd('meta:{}:{}'.format(query_hash, file_path), json.dumps(flat_meta))


def execute_job(job_id, hash):
    logging.info('Parsing...')

    job = convert_dict(redis.hgetall(job_id))
    yara_rule = job['raw_yara']

    redis.hmset(job_id, {
        'status': 'processing',
        'timestamp': time.time(),
    })

    try:
        rules = plyara.Plyara().parse_string(yara_rule)
        parser = YaraParser(rules[0])
        parsed = parser.parse()
    except Exception as e:
        logging.exception(e)
        raise RuntimeError('Failed to parse Yara')

    redis.hmset(job_id, {
        'status': 'querying',
        'timestamp': time.time(),
    })

    logging.info('Querying backend...')
    result = db.query(parsed)
    if 'error' in result:
        raise RuntimeError(result['error'])

    job = redis.hgetall(job_id)
    files = [f for f in result['files'] if f.strip()]

    logging.info('Database responded with {} files'.format(len(files)))

    if 'max_files' in job and int(job['max_files']) > 0:
        files = files[:int(job['max_files'])]

    redis.hmset(job_id, {
        'total_files': len(files),
        'files_processed': 0,
    })

    logging.info('Compiling Yara')
    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception('Yara parse error')
        raise e

    for file_ndx, file_path in enumerate(files):
        try:
            matches = rule.match(data=open(file_path, 'rb').read())
        except yara.Error:
            logging.exception('Yara failed to check file {}'.format(file_path))
            matches = None
        except FileNotFoundError:
            logging.exception('Failed to open file for yara check: {}'.format(file_path))
            matches = None

        if matches:
            logging.info('Processed (match): {}'.format(file_path))
            redis.sadd('matches:' + hash, file_path)
            redis.rpush('metadata-jobs', '{}:{}'.format(hash, file_path))
        else:
            logging.info('Processed (nope ): {}'.format(file_path))
            redis.sadd('false_positives:' + hash, file_path)

        redis.hmset(job_id, {
            'files_processed': file_ndx + 1,
        })

        status = redis.hget(job_id, 'status')
        if status == 'cancelled':
            logging.info('Job cancelled')
            return

    redis.hmset(job_id, {
        'status': 'done',
    })
    logging.info('Done')


if __name__ == '__main__':
    job_daemon()
