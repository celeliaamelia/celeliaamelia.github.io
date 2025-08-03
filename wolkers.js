import { connect } from "cloudflare:sockets";

// =================================================================================
// Konfigurasi Variabel
// Harap sesuaikan variabel di bawah ini dengan konfigurasi Anda.
// =================================================================================

const rootDomain = "yirijo3075.workers.dev"; // Ganti dengan domain utama Anda (jika menggunakan custom domain)
const serviceName = "asep"; // Ganti dengan nama worker Anda

// Opsional: Isi bagian ini untuk mengaktifkan fitur Manajemen Domain Wildcard.
// Jika dikosongkan, fitur akan dinonaktifkan secara otomatis.
const apiKey = ""; // Global API key Cloudflare Anda
const apiEmail = ""; // Email akun Cloudflare Anda
const accountID = ""; // Account ID Cloudflare Anda
const zoneID = ""; // Zone ID dari domain yang Anda gunakan

// =================================================================================
// Konstanta & Variabel Internal (Umumnya tidak perlu diubah)
// =================================================================================

let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];

const APP_DOMAIN = `${serviceName}.${rootDomain}`;
const PORTS = [443, 80];
const PROTOCOLS = ["trojan", "vless", "ss"];
const KV_PROXY_URL = "https://raw.githubusercontent.com/datayumiwandi/shiroko/refs/heads/main/Data/Alive.json";
const PROXY_BANK_URL = "https://raw.githubusercontent.com/Mayumiwandi/Emilia/refs/heads/main/Data/alive.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const REVERSE_PROXY_TARGET = "arumazeta.github.io"; // Target untuk reverse proxy

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
	"Access-Control-Allow-Headers": "*",
};

// =================================================================================
// Handler Utama Worker
// =================================================================================

export default {
	async fetch(request, env, ctx) {
		try {
			const url = new URL(request.url);

			// Handle OPTIONS request untuk CORS preflight
			if (request.method === 'OPTIONS') {
				return new Response(null, { headers: CORS_HEADERS });
			}

			// Cek apakah API untuk manajemen domain siap (aktif)
			if (apiKey && apiEmail && accountID && zoneID) {
				isApiReady = true;
			}

			// Handler untuk koneksi WebSocket dari klien proxy
			const upgradeHeader = request.headers.get("Upgrade");
			if (upgradeHeader === "websocket") {
				const proxyMatch = url.pathname.match(/^\/(.+[:-]\d+)$/);
				if (url.pathname.length === 3 || url.pathname.includes(",")) {
					const proxyKeys = url.pathname.replace("/", "").toUpperCase().split(",");
					const proxyKey = proxyKeys[Math.floor(Math.random() * proxyKeys.length)];
					const kvProxy = await getKVProxyList(env.KV_PROXY_URL);
					if (kvProxy[proxyKey] && kvProxy[proxyKey].length > 0) {
						proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];
						return await websocketHandler(request);
					}
				} else if (proxyMatch) {
					proxyIP = proxyMatch[1];
					return await websocketHandler(request);
				}
				// Jika tidak ada proxy yang cocok, tolak koneksi
				return new Response("Proxy not found", { status: 404 });
			}

			// Router untuk request API
			if (url.pathname.startsWith("/api/v1")) {
				return await handleApiRequest(url, request, env);
			}
			
			// Handler untuk health check proxy
			if (url.pathname.startsWith("/check")) {
				const targetParam = url.searchParams.get("target");
				if (!targetParam) return new Response("Missing target parameter", { status: 400, headers: CORS_HEADERS });
				const target = targetParam.split(":");
				const result = await checkProxyHealth(target[0], target[1] || "443");
				return new Response(JSON.stringify(result), {
					status: 200,
					headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
				});
			}

			// Fallback untuk request lain: Reverse Proxy ke target
			return await reverseProxy(request, REVERSE_PROXY_TARGET);

		} catch (err) {
			console.error(err);
			return new Response(`An error occurred: ${err.toString()}`, {
				status: 500,
				headers: CORS_HEADERS,
			});
		}
	},
};

// =================================================================================
// Handler API
// =================================================================================

async function handleApiRequest(url, request, env) {
	const apiPath = url.pathname.replace("/api/v1", "");

	// Endpoint BARU untuk memeriksa status API
	if (apiPath === "/status") {
		return new Response(JSON.stringify({ domainApiReady: isApiReady }), {
			status: 200,
			headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
		});
	}

	// Endpoint untuk mendapatkan daftar proxy mentah dalam format JSON
	if (apiPath === "/proxies") {
		const countrySelect = url.searchParams.get("cc")?.toUpperCase().split(",");
		const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL || PROXY_BANK_URL;
		
		let proxyList = await getProxyList(proxyBankUrl);

		if (countrySelect && countrySelect.length > 0) {
			proxyList = proxyList.filter(proxy => countrySelect.includes(proxy.country));
		}

		return new Response(JSON.stringify(proxyList), {
			status: 200,
			headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
		});
	}

	// Endpoint untuk mendapatkan info GeoIP klien
	if (apiPath === "/myip") {
		return new Response(
			JSON.stringify({
				ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
				colo: request.headers.get("cf-ray")?.split("-")[1],
				...request.cf,
			}), {
				headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
			}
		);
	}
	
	// Endpoint untuk manajemen domain (jika API diaktifkan)
	if (apiPath.startsWith("/domains")) {
		if (!isApiReady) {
			return new Response(JSON.stringify({ success: false, message: "API for domain management is not configured on the worker." }), { status: 501, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
		}

		const cloudflareApi = new CloudflareApi();
		const wildcardApiPath = apiPath.replace("/domains", "");

		if (wildcardApiPath === "/get") {
			const domains = await cloudflareApi.getDomainList();
			return new Response(JSON.stringify({ success: true, result: domains }), { headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
		} else if (wildcardApiPath === "/put") {
			const domain = url.searchParams.get("domain");
			if (!domain) {
				return new Response(JSON.stringify({ success: false, message: "Domain parameter is missing." }), { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
			}
			const { success, status, message } = await cloudflareApi.registerDomain(domain);
			return new Response(JSON.stringify({ success, message }), { status, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
		}
	}

	// Endpoint untuk menghasilkan link langganan (misal: Clash)
	// Dipertahankan jika dibutuhkan di masa depan
	if (apiPath.startsWith("/yumi")) {
		return await generateSubscription(url, env);
	}

	return new Response(JSON.stringify({ success: false, message: "API endpoint not found." }), { status: 404, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
}

// =================================================================================
// Class untuk Interaksi dengan Cloudflare API
// =================================================================================

class CloudflareApi {
    constructor() {
        this.headers = {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
        };
    }

    async getDomainList() {
        const url = `https://api.cloudflare.com/client/v4/accounts/${accountID}/workers/domains`;
        try {
            const res = await fetch(url, { headers: this.headers });
            if (!res.ok) {
                console.error("Failed to get domain list:", await res.text());
                return [];
            }
            const respJson = await res.json();
            if (respJson.success && respJson.result) {
                return respJson.result
                    .filter(data => data.service === serviceName)
                    .map(data => data.hostname);
            }
            return [];
        } catch (error) {
            console.error("Error in getDomainList:", error);
            return [];
        }
    }

    async registerDomain(domain) {
        // Asumsi frontend mengirim subdomain saja, misal "test"
        // Backend akan menggabungkannya dengan rootDomain
        const fullDomain = `${domain}.${rootDomain}`.toLowerCase();
        
        const url = `https://api.cloudflare.com/client/v4/accounts/${accountID}/workers/domains`;
        const body = JSON.stringify({
            hostname: fullDomain,
            service: serviceName,
            zone_id: zoneID,
        });

        try {
            const res = await fetch(url, { method: "PUT", headers: this.headers, body });
            const respJson = await res.json();

            if (respJson.success) {
                return { success: true, status: 200, message: `Successfully registered ${fullDomain}` };
            } else {
                const error = respJson.errors[0];
                // Kode 10012: Domain sudah ada
                const message = error.code === 10012 ? `Domain ${fullDomain} already exists.` : error.message;
                return { success: false, status: res.status, message: message };
            }
        } catch (error) {
            console.error("Error in registerDomain:", error);
            return { success: false, status: 500, message: "An internal error occurred." };
        }
    }
}

// =================================================================================
// Fungsi Helper & Logika Inti
// =================================================================================

/**
 * Fungsi BARU untuk melakukan reverse proxy.
 * Mengambil request dan meneruskannya ke domain target.
 * @param {Request} request
 * @param {string} target
 * @returns {Promise<Response>}
 */
async function reverseProxy(request, target) {
    const url = new URL(request.url);
    url.hostname = target;

    const modifiedRequest = new Request(url, request);
    modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

    const response = await fetch(modifiedRequest);
    const newResponse = new Response(response.body, response);

    // Atur header CORS pada respons yang di-proxy
    for (const [key, value] of Object.entries(CORS_HEADERS)) {
        newResponse.headers.set(key, value);
    }
    newResponse.headers.set("X-Proxied-By", "Cloudflare-Worker-Yumi");

    return newResponse;
}

async function getKVProxyList(kvProxyUrl = KV_PROXY_URL) {
	if (!kvProxyUrl) return {};
	try {
		const response = await fetch(kvProxyUrl);
		if (response.ok) {
			return await response.json();
		}
	} catch (error) {
		console.error("Error fetching KV Proxy List:", error);
	}
	return {};
}

async function getProxyList(proxyBankUrl = PROXY_BANK_URL) {
    if (cachedProxyList.length > 0) {
        return cachedProxyList;
    }
	if (!proxyBankUrl) return [];
	try {
		const response = await fetch(proxyBankUrl);
		if (response.ok) {
			const text = await response.text();
			cachedProxyList = text
				.split("\n")
				.filter(Boolean)
				.map((entry) => {
					const [proxyIP, proxyPort, country, org] = entry.split(",");
					return {
						proxyIP: proxyIP || "Unknown",
						proxyPort: proxyPort || "Unknown",
						country: country || "Unknown",
						org: org || "Unknown Org",
					};
				});
            return cachedProxyList;
		}
	} catch (error) {
		console.error("Error fetching Proxy Bank List:", error);
	}
	return [];
}

function reverse(s) {
	return s.split("").reverse().join("");
}

function shuffleArray(array) {
	for (let i = array.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[array[i], array[j]] = [array[j], array[i]];
	}
}

async function generateSubscription(url, env) {
	const filterCC = url.searchParams.get("cc")?.split(",") || [];
	const filterPort = url.searchParams.get("port")?.split(",") || PORTS.map(String);
	const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
	const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
	const filterFormat = url.searchParams.get("format") || "raw";
	const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;
	const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL || PROXY_BANK_URL;

	let proxyList = await getProxyList(proxyBankUrl);
	
	if (filterCC.length) {
		proxyList = proxyList.filter((proxy) => filterCC.includes(proxy.country));
	}
	shuffleArray(proxyList);

	const uuid = crypto.randomUUID();
	const result = [];

	for (const proxy of proxyList) {
		if (result.length >= filterLimit) break;
		const uri = new URL(`${reverse("najort")}://${fillerDomain}`);
		uri.searchParams.set("encryption", "none");
		uri.searchParams.set("type", "ws");
		uri.searchParams.set("host", fillerDomain);

		for (const port of filterPort) {
			for (const protocol of filterVPN) {
				if (result.length >= filterLimit) break;
				
				uri.protocol = protocol;
				uri.port = port.toString();
				uri.searchParams.set("path", `/${proxy.proxyIP}-${proxy.proxyPort}`);
				uri.searchParams.set("security", port == 443 ? "tls" : "none");
				uri.searchParams.set("sni", port == 80 && protocol === "vless" ? "" : fillerDomain);

				if (protocol === "ss") {
					uri.username = btoa(`none:${uuid}`);
					uri.searchParams.set(
						"plugin",
						`v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxy.proxyIP}-${proxy.proxyPort};host=${fillerDomain}`
					);
				} else {
					uri.username = uuid;
					uri.searchParams.delete("plugin");
				}
				
				uri.hash = `${result.length + 1} ${proxy.country} ${proxy.org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
				result.push(uri.toString());
			}
		}
	}

	let finalResult = "";
	switch (filterFormat) {
		case "raw":
			finalResult = result.join("\n");
			break;
		case "clash":
		case "sfa":
		case "bfr":
			const res = await fetch(CONVERTER_URL, {
				method: "POST",
				body: JSON.stringify({
					url: result.join(","),
					format: filterFormat,
					template: "cf",
				}),
			});
			if (res.ok) {
				finalResult = await res.text();
			} else {
				return new Response(res.statusText, { status: res.status, headers: CORS_HEADERS });
			}
			break;
		default:
			return new Response("Unsupported format", { status: 400, headers: CORS_HEADERS });
	}

	return new Response(finalResult, { status: 200, headers: CORS_HEADERS });
}


// =================================================================================
// Logika WebSocket & Protokol Proxy (Tidak diubah)
// =================================================================================

async function websocketHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let addressLog = "";
    let portLog = "";
    const log = (info, event) => {
        console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = {
        value: null,
    };
    let isDNS = false;
    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (isDNS) {
                        return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log);
                    }
                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }
                    const protocol = await protocolSniffer(chunk);
                    let protocolHeader;
                    if (protocol === reverse("najorT")) {
                        protocolHeader = parseNajortHeader(chunk);
                    } else if (protocol === reverse("SSELV")) {
                        protocolHeader = parseSselvHeader(chunk);
                    } else if (protocol === reverse("skcoswodahS")) {
                        protocolHeader = parseSsHeader(chunk);
                    } else {
                        throw new Error("Unknown Protocol!");
                    }
                    addressLog = protocolHeader.addressRemote;
                    portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
                    if (protocolHeader.hasError) {
                        throw new Error(protocolHeader.message);
                    }
                    if (protocolHeader.isUDP) {
                        if (protocolHeader.portRemote === 53) {
                            isDNS = true;
                        } else {
                            throw new Error("UDP only support for DNS port 53");
                        }
                    }
                    if (isDNS) {
                        return handleUDPOutbound(
                            DNS_SERVER_ADDRESS,
                            DNS_SERVER_PORT,
                            chunk,
                            webSocket,
                            protocolHeader.version,
                            log
                        );
                    }
                    handleTCPOutBound(
                        remoteSocketWrapper,
                        protocolHeader.addressRemote,
                        protocolHeader.portRemote,
                        protocolHeader.rawClientData,
                        webSocket,
                        protocolHeader.version,
                        log
                    );
                },
                close() {
                    log(`readableWebSocketStream is close`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is abort`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream pipeTo error", err);
        });
    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function protocolSniffer(buffer) {
    if (buffer.byteLength >= 62) {
        const najortDelimiter = new Uint8Array(buffer.slice(56, 60));
        if (najortDelimiter[0] === 0x0d && najortDelimiter[1] === 0x0a) {
            if (najortDelimiter[2] === 0x01 || najortDelimiter[2] === 0x03 || najortDelimiter[2] === 0x7f) {
                if (najortDelimiter[3] === 0x01 || najortDelimiter[3] === 0x03 || najortDelimiter[3] === 0x04) {
                    return reverse("najorT");
                }
            }
        }
    }
    const sselvDelimiter = new Uint8Array(buffer.slice(1, 17));
    if (arrayBufferToHex(sselvDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
        return reverse("SSELV");
    }
    return reverse("skcoswodahS"); // default
}

async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    responseHeader,
    log
) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }
    async function retry() {
        const tcpSocket = await connectAndWrite(
            proxyIP.split(/[:-]/)[0] || addressRemote,
            proxyIP.split(/[:-]/)[1] || portRemote
        );
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
    try {
        let protocolHeader = responseHeader;
        const tcpSocket = connect({
            hostname: targetAddress,
            port: targetPort,
        });
        log(`Connected to ${targetAddress}:${targetPort}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(
            new WritableStream({
                async write(chunk) {
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        if (protocolHeader) {
                            webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
                            protocolHeader = null;
                        } else {
                            webSocket.send(chunk);
                        }
                    }
                },
                close() {
                    log(`UDP connection to ${targetAddress} closed`);
                },
                abort(reason) {
                    console.error(`UDP connection to ${targetPort} aborted due to ${reason}`);
                },
            })
        );
    } catch (e) {
        console.error(`Error while handling UDP outbound, error ${e.message}`);
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
    return stream;
}

function parseSsHeader(ssBuffer) {
    const view = new DataView(ssBuffer);
    const addressType = view.getUint8(0);
    let addressLength = 0;
    let addressValueIndex = 1;
    let addressValue = "";
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `Invalid addressType for ${reverse("skcoswodahS")}: ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `Destination address empty, address type is: ${addressType}`,
        };
    }
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: portIndex + 2,
        rawClientData: ssBuffer.slice(portIndex + 2),
        version: null,
        isUDP: portRemote == 53,
    };
}

function parseSselvHeader(buffer) {
    const version = new Uint8Array(buffer.slice(0, 1));
    let isUDP = false;
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    if (cmd === 1) {} else if (cmd === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
        case 1: // For IPv4
            addressLength = 4;
            addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2: // For Domain
            addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: // For IPv6
            addressLength = 16;
            const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        rawClientData: buffer.slice(addressValueIndex + addressLength),
        version: new Uint8Array([version[0], 0]),
        isUDP: isUDP,
    };
}

function parseNajortHeader(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data",
        };
    }
    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) {
        isUDP = true;
    } else if (cmd != 1) {
        throw new Error("Unsupported command type!");
    }
    let addressType = view.getUint8(1);
    let addressLength = 0;
    let addressValueIndex = 2;
    let addressValue = "";
    switch (addressType) {
        case 1: // For IPv4
            addressLength = 4;
            addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
                "."
            );
            break;
        case 3: // For Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 4: // For IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${addressType}`,
        };
    }
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: portIndex + 4,
        rawClientData: socks5DataBuffer.slice(portIndex + 4),
        version: null,
        isUDP: isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {},
                async write(chunk, controller) {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket.readyState is not open, maybe close");
                    }
                    if (header) {
                        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                        header = null;
                    } else {
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`remoteSocketToWS has exception `, error.stack || error);
            safeCloseWebSocket(webSocket);
        });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

async function checkProxyHealth(proxyIP, proxyPort) {
	try {
		const response = await fetch(`https://id1.foolvpn.me/api/v1/check?ip=${proxyIP}:${proxyPort}`, { signal: AbortSignal.timeout(3000) });
		if (response.ok) {
			return await response.json();
		}
	} catch (error) {
		// Abaikan error timeout atau fetch, kembalikan status tidak aktif
	}
	return { proxyip: false };
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

function arrayBufferToHex(buffer) {
    return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
