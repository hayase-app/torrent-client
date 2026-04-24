import fetch from 'cross-fetch-ponyfill'
import { XMLParser } from 'fast-xml-parser'

type SoapArgs = Record<string, string | number | boolean>

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  parseTagValue: false,
  removeNSPrefix: true,
  trimValues: true
})

const xmlEscapeMap: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;'
}

export const escapeXml = (value: string) => value.replace(/[&<>"']/g, char => xmlEscapeMap[char] ?? char)

const extractFault = (fault: Record<string, unknown>) => {
  const generic = typeof fault.faultstring === 'string' ? fault.faultstring : undefined
  if (generic) return generic

  const detail = fault.detail
  if (!detail || typeof detail !== 'object') return undefined

  const upnpError = (detail as Record<string, unknown>).UPnPError
  if (!upnpError || typeof upnpError !== 'object') return undefined

  const code = typeof (upnpError as Record<string, unknown>).errorCode === 'string'
    ? (upnpError as Record<string, unknown>).errorCode
    : undefined
  const description = typeof (upnpError as Record<string, unknown>).errorDescription === 'string'
    ? (upnpError as Record<string, unknown>).errorDescription
    : undefined

  if (!code && !description) return undefined

  return [code, description].filter(Boolean).join(': ')
}

const toBody = (raw: string) => {
  const parsed = parser.parse(raw) as Record<string, unknown>
  const envelope = (parsed.Envelope ?? parsed['s:Envelope']) as Record<string, unknown> | undefined
  const body = (envelope?.Body ?? parsed.Body ?? parsed['s:Body']) as Record<string, unknown> | undefined
  return body
}

export const buildSoapEnvelope = (serviceType: string, action: string, args: SoapArgs = {}) => {
  const payload = Object.entries(args)
    .map(([key, value]) => `<${key}>${escapeXml(String(value))}</${key}>`)
    .join('')

  return '<?xml version="1.0" encoding="utf-8"?>\n' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:${action} xmlns:u="${escapeXml(serviceType)}">${payload}</u:${action}></s:Body>` +
    '</s:Envelope>'
}

export const soapRequest = async (
  endpoint: string,
  serviceType: string,
  action: string,
  args: SoapArgs = {}
) => {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset="utf-8"',
      SOAPACTION: `"${serviceType}#${action}"`
    },
    body: buildSoapEnvelope(serviceType, action, args)
  })

  const text = await response.text()
  const body = toBody(text)

  if (!body) {
    if (!response.ok) {
      throw new Error(`SOAP request failed (${response.status}): ${response.statusText}`)
    }

    return {}
  }

  const fault = body.Fault
  if (fault && typeof fault === 'object') {
    throw new Error(extractFault(fault as Record<string, unknown>) ?? `SOAP action failed: ${action}`)
  }

  const actionResponseKey = `${action}Response`
  const actionResponse = body[actionResponseKey]

  if (!response.ok && !actionResponse) {
    throw new Error(`SOAP request failed (${response.status}): ${response.statusText}`)
  }

  if (actionResponse && typeof actionResponse === 'object') {
    return actionResponse as Record<string, unknown>
  }

  const fallbackResponse = Object.entries(body)
    .find(([key]) => key.endsWith('Response'))

  if (fallbackResponse?.[1] && typeof fallbackResponse[1] === 'object') {
    return fallbackResponse[1] as Record<string, unknown>
  }

  return {}
}
