FROM node:20-alpine

# Add alternate shells so CMDI_SHELL can be switched between
# /bin/sh, /bin/bash, and /bin/zsh in the command-injection lab.
RUN apk add --no-cache bash zsh iputils

WORKDIR /app

CMD ["sh", "-c", "npm install --no-audit --no-fund && npm start"]
