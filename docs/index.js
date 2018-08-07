import * as codeMirror from 'codemirror'
import * as xml from 'codemirror/mode/xml/xml'
import { SignedXml, xpath }  from 'xml-crypto'
import { DOMParser } from 'xmldom'

const textArea = document.getElementById('target-text-area')
const certArea = document.getElementById('cert-text-area')
const status = document.getElementById('status')
const editor = codeMirror.fromTextArea(textArea, { lineWrapping: true, mode: 'xml', theme: 'monokai', viewportMargin: Infinity })
const certEditor = codeMirror.fromTextArea(certArea, { lineWrapping: true, mode: 'xml', theme: 'monokai', viewportMargin: Infinity })

function validate(instance) {
  const extraSecurity = document.location.search === '?extra-secure'
  const cert = certEditor.getValue()
  console.log(cert)
  let res = false
  try {
    const xml = instance.getValue()
    const doc = new DOMParser().parseFromString(xml)
    const signature = xpath(doc, "//*[local-name(.)='Signature']")[0]
    const sig = new SignedXml()
    sig.keyInfoProvider = {
      getKeyInfo: () => "<X509Data></X509Data>",
      getKey: () => cert
    }
    sig.loadSignature(signature)
    res = sig.checkSignature(xml)
    if (extraSecurity) {
      const refUri = sig.references[0].uri.substring(1)
      const ass = xpath(doc, "/*/*[local-name(.) = 'Assertion']")[0]
      console.log('ass', ass)
      const idAttribute = ass.getAttribute('ID') ? 'ID' : 'Id';
      console.log('idAttribute', idAttribute)
      if (ass.getAttribute(idAttribute) !== refUri) { res = false }
      if (xpath(doc, "//*[@" + idAttribute + "]").length > 1) { res = false }
    }
  }
  catch(err) {
    status.innerText = '' + err
    document.body.className = 'invalid-saml'
    return;
  }
  status.innerText = res ? 'Signature is VALID' : 'Signature is NOT VALID'
  document.body.className = res ? 'valid-saml' : 'invalid-saml'
}

validate(editor)
editor.on('change', validate)
certEditor.on('change', certEditor => { validate(editor) })

