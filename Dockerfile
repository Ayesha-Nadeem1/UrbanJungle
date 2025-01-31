# FROM python:3.12.8-bullseye

# RUN apt-get update && apt-get install -y netcat-openbsd

# WORKDIR /code

# COPY requirements.txt /code/
# RUN pip install --upgrade pip && \
#     pip install -r requirements.txt

# COPY . /code/

# # Use a shell script to handle waiting and starting
# COPY entrypoint.sh /entrypoint.sh
# RUN chmod +x /entrypoint.sh

# ENTRYPOINT ["/entrypoint.sh"]
FROM python:3.12.8-bullseye

RUN apt-get update && apt-get install -y netcat-openbsd

WORKDIR /code

COPY requirements.txt /code/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . /code/

# Copy wait-for-it script
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

# Remove custom entrypoint
# ENTRYPOINT ["/entrypoint.sh"]