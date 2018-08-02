import hashlib
import json
import logging
import os
import time

from flask import Flask, request, redirect, url_for, Response, jsonify, send_file
from itsdangerous import BadSignature
from werkzeug.exceptions import Forbidden
from zmq import Again

from lib.ursadb import UrsaDb
from lib.yaraparse import YaraParser
import plyara

from util import make_redis, make_serializer, convert_list, convert_dict
import config

redis = make_redis()
app = Flask(__name__)
s = make_serializer()
db = UrsaDb(config.BACKEND)


@app.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'cache-control,x-requested-with,content-type,authorization'
    response.headers['Access-Control-Allow-Methods'] = 'POST, PUT, GET, OPTIONS'
    return response


@app.route('/saved-rules')
def get_saved_rules():
    named_queries = redis.keys('named_query:*')
    saved_rules = []
    for query in named_queries:
        qid = query.split(':')[1]
        name = redis.get(query)
        saved_rules.append({'id': qid, 'name': name})
    return jsonify({"saved_rules": sorted(saved_rules, key=lambda x: x['name'])})


@app.route('/admin/index', methods=['POST'])
def admin_index():
    path = request.form['path']

    if path not in config.INDEXABLE_PATHS:
        return jsonify({"error": "location denied"}), 403

    tasks = db.status().get('result', {}).get('tasks', [])

    if any(task['request'].startswith('index ') for task in tasks):
        return jsonify({"error": "index already queued"}), 400

    redis.rpush('index-jobs', path)
    return jsonify({"status": "queued"})


@app.route('/download/<access_token>')
def download(access_token):
    try:
        sample_fname = s.loads(access_token)
    except BadSignature:
        raise Forbidden('Invalid access token. Corrupted URL or unauthorized access.')

    attach_name, ext = os.path.splitext(os.path.basename(sample_fname))

    if ext:
        ext = ext + '_'

    return send_file(sample_fname, as_attachment=True, attachment_filename=attach_name + ext)


@app.route('/query', methods=['POST'])
def query():
    req = request.get_json()

    raw_yara = req['rawYara']

    try:
        rules = plyara.Plyara().parse_string(raw_yara)
    except Exception as e:
        return jsonify({'error': 'PLYara failed (not my fault): ' + str(e)}), 400

    if len(rules) > 1:
        return jsonify({'error': 'More than one rule specified!'}), 400

    rule_name = rules[0].get('rule_name')

    try:
        parser = YaraParser(rules[0])
        pre_parsed = parser.pre_parse()
        parsed = parser.parse()
    except Exception as e:
        print('fucked up')
        logging.exception('YaraParser failed')
        return jsonify({'error': 'YaraParser failed (msm\'s fault): {}'.format(str(e))}), 400

    if req['method'] == 'parse':
        return jsonify({'rule_name': rule_name, "parsed": parsed})

    qhash = hashlib.sha256(raw_yara.encode('utf-8')).hexdigest()
    p = redis.pipeline()
    p.delete('matches:' + qhash, 'false_positives:' + qhash, 'job:' + qhash, 'meta:' + qhash + ':*')

    job_id = 'job:' + qhash
    job_obj = {
        'status': 'new',
        'max_files': -1,
        'rule_name': rule_name,
        'parsed': parsed,
        'pre_parsed': pre_parsed,
        'raw_yara': raw_yara,
        'submitted': int(time.time())
    }

    if req['method'] == 'query_100':
        job_obj.update({'max_files': 100})

    p.hmset(job_id, job_obj)
    p.rpush(b'jobs', qhash)

    print(p.execute())
    return jsonify({'query_hash': qhash})


def generate_match_objs(hash, matches):
    signed_matches = []

    for m in matches:
        obj = {
            "matched_path": m,
            "download_url": url_for('download', access_token=s.dumps(m), _external=True),
            "metadata_available": False,
            "metadata": {}
        }

        meta_set = redis.smembers("meta:{}:{}".format(hash, m))

        if meta_set:
            obj.update({
                "metadata_available": True,
                "metadata": json.loads(list(meta_set)[0])
            })

        signed_matches.append(obj)

    return signed_matches


@app.route('/status/<hash>')
def status(hash):
    matches = convert_list(redis.smembers('matches:' + hash))
    job = redis.hgetall('job:' + hash)
    error = job.get('error')

    return jsonify({
        "matches": generate_match_objs(hash, matches),
        "job": convert_dict(job),
        "error": error
    })


@app.route('/matches/<hash>')
def matches(hash):
    matches = convert_list(redis.smembers('matches:' + hash))
    mobjs = generate_match_objs(hash, matches)
    signed_matches = [url_for('sample', name=m["matched_dump"], _external=True)
                      + ' # ' + m["binary_hash"] for m in mobjs]

    return Response('\n'.join(signed_matches), content_type='text/plain')


@app.route('/save', methods=['POST'])
def save():
    qhash = request.form.get('hash')
    rule_name = request.form.get('rule_name')
    redis.set('named_query:{}'.format(qhash), rule_name)
    return redirect(url_for('query_by_hash', qhash=qhash))


@app.route('/job/<job_id>', methods=['DELETE'])
def admin_cancel(job_id):
    redis.hmset('job:' + job_id, {
        'status': 'cancelled',
    })


@app.route('/status/jobs')
def status_jobs():
    jobs = redis.keys('job:*')
    jobs = sorted([dict({'id': job[4:].decode('utf-8')}, **convert_dict(redis.hgetall(job))) for job in jobs],
                  key=lambda o: o.get('submitted'), reverse=True)

    return jsonify({"jobs": jobs})


@app.route('/status/backend')
def status_backend():
    db_alive = True

    try:
        tasks = db.status().get('result', {}).get('tasks', [])
    except Again:
        db_alive = False
        tasks = []

    return jsonify({
        "db_alive": db_alive,
        "tasks": tasks,
    })


@app.route('/admin/indexable_paths')
def admin_indexable_paths():
    return jsonify({
        "indexable_paths": config.INDEXABLE_PATHS
    })


if __name__ == "__main__":
    app.run()
