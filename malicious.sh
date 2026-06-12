#!/bin/bash
echo "Trying network access..."
curl -s http://example.com -o /dev/null
echo "Exit code of curl: $?"
