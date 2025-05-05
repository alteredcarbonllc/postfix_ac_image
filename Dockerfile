FROM ubuntu:24.04

RUN groupadd -g 55004 vmail
RUN useradd -u 55004 -g 55004 \
    -d /var/mail \
    -s /usr/sbin/nologin \
    -M vmail

    
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
    postfix \
    postfix-mysql \
    postfix-pgsql \
    nano \
    && rm -rf /var/lib/apt/lists/*

#RUN deluser postfix || true && delgroup postfix || true

#RUN groupadd -g 55004 postfix
#RUN useradd -u 55004 -g 55004 \
#    -d /var/spool/postfix \
#    -s /usr/sbin/nologin \
#    -M postfix


#RUN chown -R postfix:postfix /var/spool/postfix

# Устанавливаем права на почтовый каталог
RUN mkdir -p /var/mail && \
    chown -R vmail:vmail /var/mail


# Экспонируем стандартный порт Postfix
EXPOSE 25 465 587

# Переключаемся на пользователя postgres
USER root

#RUN chown postgres:postgres /var/lib/postgresql/data

CMD ["postfix", "start-fg"]
