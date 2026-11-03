"""Report generator + final eval, Kareem Saleh

Contract:
    python -m src.reporter --db logs/dns_proxy.db --out report/
    Reads Vinh's SQLite, makes blocked/allowed charts, prints:
      block rate, FP/FN, avg latency (proxy vs direct).

Requirements:
- Final eval: 500 benign (Tranco) + 500 malicious (feeds) through proxy.
- Charts: matplotlib bar/pie (blocked by category, allow vs block).
- Also owns README run instructions.
"""
# TODO: import sqlite3, matplotlib, argparse, time
import sqlite3
import argparse
import time
import os
import matplotlib.pyplot as plt
from dnslib import DNSRecord

def run_evaluation(proxy_host: str = "127.0.0.1", proxy_port: int = 5353,
                   benign_file: str = "data/benign500.txt",
                   malicious_file: str = "data/malicious500.txt") -> dict:
    """TODO: send 1000 queries, collect decisions, compute:
    returns {'block_rate':..,'fp':..,'fn':..,'avg_latency_ms':.., 'direct_avg_ms':..}
    """
    benign = []
    with open(benign_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                benign.append(domain)

    malicious = []
    with open(malicious_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                malicious.append(domain)

    errors = 0

    fp = 0
    latencies = []
    for domain in benign:
        try:
            question = DNSRecord.question(domain)
            start = time.time()
            reply_bytes = question.send(proxy_host, proxy_port, timeout=2)
            elapsed_ms = (time.time() - start) * 1000
            reply = DNSRecord.parse(reply_bytes)
            ip = str(reply.rr[0].rdata)
        except Exception:
            errors = errors + 1
            continue
        latencies.append(elapsed_ms)
        if ip == "0.0.0.0":
            fp = fp + 1

    fn = 0
    malicious_answered = 0
    for domain in malicious:
        try:
            question = DNSRecord.question(domain)
            reply_bytes = question.send(proxy_host, proxy_port, timeout=2)
            reply = DNSRecord.parse(reply_bytes)
            ip = str(reply.rr[0].rdata)
        except Exception:
            errors = errors + 1
            continue
        malicious_answered = malicious_answered + 1
        if ip != "0.0.0.0":
            fn = fn + 1

    direct_latencies = []
    for domain in benign:
        try:
            question = DNSRecord.question(domain)
            start = time.time()
            question.send("8.8.8.8", 53, timeout=2)
            elapsed_ms = (time.time() - start) * 1000
        except Exception:
            continue
        direct_latencies.append(elapsed_ms)

    benign_answered = len(latencies)

    avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0
    direct_avg_ms = sum(direct_latencies) / len(direct_latencies) if direct_latencies else 0.0

    blocked_bad = malicious_answered - fn
    block_rate = blocked_bad / malicious_answered if malicious_answered else 0.0
    fp_rate = fp / benign_answered if benign_answered else 0.0
    fn_rate = fn / malicious_answered if malicious_answered else 0.0

    return {
        'block_rate': block_rate,
        'fp': fp,
        'fn': fn,
        'tp': malicious_answered - fn,
        'tn': benign_answered - fp,
        'fp_rate': fp_rate,
        'fn_rate': fn_rate,
        'errors': errors,
        'avg_latency_ms': avg_latency_ms,
        'direct_avg_ms': direct_avg_ms,
    }                                        


    


def generate_charts(db_path: str, out_dir: str) -> None:
    """TODO: query logger DB, save blocked_by_category.png + decisions.png."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT decision, COUNT(*) FROM queries GROUP BY decision"
    ).fetchall()
    decisions = dict(rows) 

    rows = conn.execute(
        "SELECT category, COUNT(*) FROM queries WHERE decision = 'block' GROUP BY category"
    ).fetchall()                                                  
    conn.close()                                                  

    categories = {}                                               
    for category, count in rows:                                  
        name = category.split(":")[0]                             
        categories[name] = categories.get(name, 0) + count        

    os.makedirs(out_dir, exist_ok=True)                           

    plt.figure()                                                  
    plt.pie(decisions.values(), labels=decisions.keys(), autopct="%1.0f%%") 
    plt.title("Query decisions")                                  
    plt.savefig(os.path.join(out_dir, "decisions.png"), bbox_inches="tight")  
    plt.close()                                                   

    plt.figure()                                                  
    bars = plt.bar(list(categories.keys()), list(categories.values())) 
    plt.bar_label(bars)                                          
    plt.gca().yaxis.get_major_locator().set_params(integer=True)  
    plt.title("Blocked queries by category")                      
    plt.ylabel("Blocked queries")                                
    plt.savefig(os.path.join(out_dir, "blocked_by_category.png"), bbox_inches="tight")  # save the picture
    plt.close()                                                  


def generate_eval_charts(results: dict, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)                           

    if results['tp'] + results['fn'] > 0:                         
        plt.figure()                                              
        plt.pie([results['tp'], results['fn']],                   
                labels=["Blocked (TP)", "Missed (FN)"], autopct="%1.0f%%")  
        plt.title("Malicious domains")                            
        plt.savefig(os.path.join(out_dir, "malicious_results.png"), bbox_inches="tight")  
        plt.close()                                               
    else:
        print("No malicious results to chart")                    

    if results['tn'] + results['fp'] > 0:                         
        plt.figure()                                              
        plt.pie([results['tn'], results['fp']],                  
                labels=["Allowed (TN)", "Blocked (FP)"], autopct="%1.0f%%")  
        plt.title("Benign domains")                               
        plt.savefig(os.path.join(out_dir, "benign_results.png"), bbox_inches="tight")  
        plt.close()                                               
    else:
        print("No benign results to chart")                                                                         

if __name__ == "__main__":
    # TODO: argparse --db --out, call generate_charts + print stats
    parser = argparse.ArgumentParser()                    
    parser.add_argument("--db", default="logs/dns_proxy.db")
    parser.add_argument("--out", default="report/")
    args = parser.parse_args()

    generate_charts(args.db, args.out)                    

    results = run_evaluation()                            
    generate_eval_charts(results, args.out)              

    print("Block rate:", results['block_rate'])
    print("True positives:", results['tp'])
    print("True negatives:", results['tn'])
    print("False positives:", results['fp'])
    print("False negatives:", results['fn'])
    print("False positive rate:", results['fp_rate'])
    print("False negative rate:", results['fn_rate'])
    print("Errors:", results['errors'])
    print("Avg latency (proxy) ms:", results['avg_latency_ms'])
    print("Avg latency (direct) ms:", results['direct_avg_ms'])
    
