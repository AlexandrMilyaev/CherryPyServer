#! venv/bin/python3
import socketserver

import cherrypy
import requests
from aiogram import Bot, types
import settings

WEBHOOK_HOST = '135.181.77.245'
WEBHOOK_PORT = 8443
WEBHOOK_LISTEN = '0.0.0.0'
WEBHOOK_SSL_CERT = 'webhook_cert.pem'
WEBHOOK_SSL_PRIV = 'webhook_pkey.pem'
WEBHOOK_URL_BASE = "https://{!s}:{!s}".format(WEBHOOK_HOST, WEBHOOK_PORT)

BOT_TEST_ADDRESS = "http://127.0.0.1:7771"
BOT_KYIV_ADDRESS = "http://127.0.0.1:7772"
BOT_DNIPRO_ADDRESS = "http://127.0.0.1:7773"

bot_test = Bot(token=settings.token_bot_test)
bot_kyiv = Bot(token=settings.token_bot_kyiv)
bot_dnipro = Bot(token=settings.token_bot_dnipro)


def bot_request(addr: str):
    if 'content-length' in cherrypy.request.headers and \
            'content-type' in cherrypy.request.headers and \
            cherrypy.request.headers['content-type'] == 'application/json':
        length = int(cherrypy.request.headers['content-length'])
        json_string = cherrypy.request.body.read(length).decode("utf-8")
        # Вот эта строчка и пересылает все входящие сообщения на нужного бота
        requests.post(addr, data=json_string)
        return ''
    else:
        raise cherrypy.HTTPError(403)


class WebhookServer(object):
    @cherrypy.expose
    def bot_test(self):
        bot_request(BOT_TEST_ADDRESS)

    @cherrypy.expose
    def bot_kyiv(self):
        bot_request(BOT_KYIV_ADDRESS)

    @cherrypy.expose
    def bot_dnipro(self):
        bot_request(BOT_DNIPRO_ADDRESS)


if __name__ == '__main__':
    cherrypy.config.update({
        'server.socket_host': WEBHOOK_LISTEN,
        'server.socket_port': WEBHOOK_PORT,
        'server.ssl_module': 'builtin',
        'server.sslcertificate': WEBHOOK_SSL_CERT,
        'server.ssl_privat_key': WEBHOOK_SSL_PRIV,
        'engine.autoreload.on': False
    })
    cherrypy.quickstart(WebhookServer(), '/', {'/': {}})


