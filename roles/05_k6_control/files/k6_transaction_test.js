/*
* This is the single, reusable k6 test script for all application-layer testing.
* It reads its configuration from environment variables passed by Ansible.
*
* - VUS: Number of concurrent Virtual Users
* - DURATION: Test duration (e.g., "120s")
* - TARGET_ENDPOINT: The URL to test (e.g., "http://10.0.0.2/")
*/

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

// A single, reusable Trend metric for all transactions
let transactionTime = new Trend('transaction_duration', true); // 'true' -> p(95) is time

// Read from environment variables, with defaults
const vus = __ENV.VUS ? parseInt(__ENV.VUS) : 10;
const duration = __ENV.DURATION || '30s';
const target = __ENV.TARGET_ENDPOINT || 'http://10.0.0.2/';

export const options = {
  vus: vus,
  duration: duration,
  thresholds: {
    // 95% of all transactions must complete in < 200ms
    'transaction_duration': ['p(95)<200'],
    // 99.9% of requests must succeed
    'http_req_failed': ['rate<0.001'],
  },
};

export default function() {
  const res = http.get(target);

  // Check for success (e.g., HTTP 200)
  const success = check(res, {
    'status is 200': (r) => r.status === 200,
  });

  // Record the duration of this transaction
  transactionTime.add(res.timings.duration);

  // Wait 1 second between iterations
  sleep(1);
}
