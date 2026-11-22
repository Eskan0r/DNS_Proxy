"""Evaluation must distinguish valid negative answers from failed queries."""
import sqlite3

from dnslib import A, CNAME, DNSRecord, QTYPE, RCODE, RR

from src.logger import QueryLogger
from src.reporter import generate_charts, run_evaluation


def test_evaluation_outcomes(tmp_path, monkeypatch):
    benign = tmp_path / 'benign.txt'
    malicious = tmp_path / 'malicious.txt'
    benign.write_text('good.com\nempty.com\nfp.com\nerror.com\n')
    malicious.write_text('bad.com\nmiss.com\ntimeout.com\nwrong.com\n')
    def send(question, host, port, timeout):
        name = str(question.q.qname).rstrip('.')
        reply = question.reply()
        if host == 'direct':
            return reply.pack()
        if name == 'timeout.com':
            raise TimeoutError()
        if name == 'wrong.com':
            reply.header.id ^= 1
        elif name == 'error.com':
            reply.header.rcode = RCODE.SERVFAIL
        elif name == 'miss.com':
            reply.header.rcode = RCODE.NXDOMAIN
        elif name in ('bad.com', 'fp.com'):
            # Sinkhole identification must inspect all address records.
            reply.add_answer(RR(question.q.qname, QTYPE.CNAME, ttl=60, rdata=CNAME('alias.com')))
            reply.add_answer(RR('alias.com', QTYPE.A, ttl=60, rdata=A('0.0.0.0')))
        elif name == 'good.com':
            reply.add_answer(RR(question.q.qname, QTYPE.A, ttl=60, rdata=A('192.0.2.1')))
        return reply.pack()
    monkeypatch.setattr(DNSRecord, 'send', send)
    result = run_evaluation(benign_file=str(benign), malicious_file=str(malicious), direct_host='direct')
    assert (result['tp'], result['tn'], result['fp'], result['fn']) == (1, 2, 1, 1)
    assert result['errors'] == 3 and result['direct_errors'] == 0
    assert result['benign_coverage'] == 3 / 4 and result['malicious_coverage'] == 2 / 4
    assert result['block_rate'] == 0.5 and result['fn_rate'] == 0.5
    assert result['fp_rate'] == 1 / 3


def test_no_answers_is_not_zero_error_rate(tmp_path, monkeypatch):
    samples = tmp_path / 'samples.txt'
    samples.write_text('example.com\n')
    def fail(*args, **kwargs):
        raise TimeoutError()
    monkeypatch.setattr(DNSRecord, 'send', fail)
    result = run_evaluation(benign_file=str(samples), malicious_file=str(samples))
    assert result['errors'] == 2 and result['direct_errors'] == 1
    assert result['block_rate'] is None and result['fp_rate'] is None
    assert result['avg_latency_ms'] is None and result['direct_avg_ms'] is None


def test_empty_database_charts(tmp_path):
    db = tmp_path / 'queries.db'
    QueryLogger(str(db)).close()
    out = tmp_path / 'charts'
    generate_charts(str(db), str(out))
    assert (out / 'decisions.png').stat().st_size > 0
    assert (out / 'blocked_by_category.png').stat().st_size > 0
