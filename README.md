# The Oprah Proxy
*Generate credentials for Opera's "browser VPN"*

!["Everybody gets a proxy" logo](logo.jpg)

Opera "VPN" introduced in Opera 38 Developer Edition is not a VPN, it's actually a proxy for the browser only, but it's free and unlimited so why not use it for some other apps, too. There's also [Opera VPN for iOS](https://itunes.apple.com/us/app/opera-free-vpn-unlimited-free/id1080756781?mt=8) and [Opera VPN for Android](https://play.google.com/store/apps/details?id=com.opera.vpn), both are real VPN. This here is about the browser one.

*Not affiliated with Opera Software AS.*

## Usage
Just run `oprahProxy.py`. You'll need an API key, the one provided **might stop working at any time**. The script will generate credentials for you and list available proxies so you can use them elsewhere. `oprahProxy.py` can also be used as a Python module in your own application. Unfortunately I've had no success using any of these proxies as a proxy for `curl` for example. But it works with OpenSSL's `s_client` tool and the script will also print the required command for you.

## Requirements
Python 3 & [Requests](http://docs.python-requests.org/). The API server works only with clients with Server Name Indication (SNI) support. Python 3 and Python 2.7.9+ include native support for SNI in their TLS modules. I was too lazy to build a version check, so I went with Python 3.

## Technical details
The proxy is a *secure* one, which means the browser talks to the proxy server via HTTPS even if it loads a plain HTTP site. Hostname resolution (*DNS*) is also done remotely on the proxy server, so the browser does not leak hostnames when using this proxy. Currently, Opera leaks IP address via WebRTC and plugins, but Opera Software is aware of it and plans to fix it in a future release.

For more technical details, including HTTP API calls, see my [technical write-up](https://gist.github.com/spaze/558b7c4cd81afa7c857381254ae7bd10).

## A message to Opera
Opera insists to call this *a browser VPN*. Sorry Opera, it's not a VPN, and calling it *a browser VPN* does not make it one. A VPN protects all connections and not just the browser ones. We've been teaching people that VPN protects their devices and operating systems and then you bake a proxy, although a secure one, in the browser and call it a VPN, that's bullshit, *pardon my French*. The feature is quite nice, but calling it *a VPN* could eventually be harmful to privacy, because of false sense of security. And then you release [Opera VPN](https://itunes.apple.com/us/app/opera-free-vpn-unlimited-free/id1080756781?mt=8) which *is* a VPN, unlike the VPN in the browser. Naming things, one of the only two hard things in Computer Science, right?

## Disclaimer
This is just for research purposes, to study how things work, no harm intended. The script might (and will) stop working at any time.

## Example `openssl s_client` command:
```
URL="http://www.opera.com" PROXY=159.203.42.222:443 HEADER="Proxy-Authorization: Basic MURBNTY1NDRFMkQ4NUZEMTgxRDY2OUUxNzM1ODg1MjI3QTRFQUNGQzpGQTI3NzIyMzhEMzg2MzlDMzYzQjk0RTA2MDc3NUIzNzMyNkIyQUEzQTM3OEVBNTdCOEVGQTUxQ0EzMjg0Qjc5"; echo -e "GET $URL HTTP/1.0\n$HEADER\n\n" | openssl s_client -connect $PROXY -ign_eof
```
Where
- `URL` is a URL you want to load, change it to fit your needs
- `PROXY` is a proxy from the list (the one in the example is the first listed proxy with port 443), change it if you want
- `HEADER` is a `Proxy-Authorization` HTTP header using generated credentials, no need to change this

## Usage with other browsers
You can use Opera's proxies with other browsers via [proxy auto-config](https://en.wikipedia.org/wiki/Proxy_auto-config) using the provided `pac.js` file. In Firefox go to *Options* → *Advanced* → *Network* → *Connection* → *Settings* and use https://raw.githubusercontent.com/spaze/oprah-proxy/master/pac.js as *Automatic proxy configuration URL*. Be aware that your browser traffic will go through the proxy server specified in the PAC file and theoretically I could change it so that the traffic goes via my own server instead. Although I'm not willing to do that, I might be forced to. **Use just for testing, at your own risk.**

When asked, use the credentials provided by `oprahProxy.py` script. The PAC file uses hardcoded location (`DE`), if you want to use other location just download the file, change the hostname (available hostnames are `{ca,de,us}.opera-proxy.net`), change your browser configuration, and you should be ready to go. Please note that Opera uses different, *numbered* hostnames when connecting to proxies (e.g. `de0.opera-proxy.net`) but these don't resolve outside of Opera. There's a certain overlap of IPs for `de.opera-proxy.net` and `de0.opera-proxy.net` so my guess is they use the same hosts with just different hostnames.
