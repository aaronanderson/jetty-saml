package com.cpsgpartners.jetty;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.eclipse.jetty.util.B64Code;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.cpsgpartners.jetty.SAMLAuthenticator.RequestHandler;
import com.cpsgpartners.jetty.SAMLAuthenticator.SAMLBinding;
import com.cpsgpartners.jetty.SAMLAuthenticator.SAMLRequest;

public class SAMLRequestHandler implements RequestHandler {

    private String _assertionConsumerServiceUrl;
    private String _issuer;
    private String _binding = "urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect";//"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private String _nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    private String _idpURL;

    private String _keyStorePath;
    private String _keyStorePassword = "samlsp";
    private KeyPair _keyPair;

    public String getAssertionConsumerServiceUrl() {
        return _assertionConsumerServiceUrl;
    }

    public void setAssertionConsumerServiceUrl(String _assertionConsumerServiceUrl) {
        this._assertionConsumerServiceUrl = _assertionConsumerServiceUrl;
    }

    public String getIssuer() {
        return _issuer;
    }

    public void setIssuer(String issuer) {
        this._issuer = issuer;
    }

    public String getBinding() {
        return _binding;
    }

    public void setBinding(String binding) {
        this._binding = binding;
    }

    public String getNameIdFormat() {
        return _nameIdFormat;
    }

    public void setNameIdFormat(String nameIdFormat) {
        this._nameIdFormat = nameIdFormat;
    }

    public String getIdpURL() {
        return _idpURL;
    }

    public void setIdpURL(String idpURL) {
        this._idpURL = idpURL;
    }

    public String getKeyStorePassword() {
        return _keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this._keyStorePassword = keyStorePassword;
    }

    public String getKeyStorePath() {
        return _keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        this._keyStorePath = keyStorePath;
        FileInputStream fis = new FileInputStream(keyStorePath);
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(fis, _keyStorePassword.toCharArray());
        Enumeration<String> aliases = p12.aliases();
        if (!aliases.hasMoreElements()) {
            throw new KeyStoreException("Empty keystore");
        }
        String alias = aliases.nextElement();
        if (aliases.hasMoreElements()) {
            throw new KeyStoreException("More than none entry in the keystore");
        }
        PrivateKey privateKey = (PrivateKey) p12.getKey(alias, _keyStorePassword.toCharArray());
        Certificate cert = p12.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        _keyPair = new KeyPair(publicKey, privateKey);

    }

    @Override
    public SAMLRequest buildAuthNRequest(HttpServletRequest request) throws IOException {
        String requestId = "id" + UUID.randomUUID().toString();
        SimpleDateFormat iidf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        String issueInstant = iidf.format(new Date());

        StringWriter xmlRequest = new StringWriter();
        //TODO support POST and Artifact Bindings. Currently only Request supported
        try {
            XMLOutputFactory xmlOutFactory = XMLOutputFactory.newInstance();
            XMLStreamWriter xsw = xmlOutFactory.createXMLStreamWriter(xmlRequest);

            xsw.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
            xsw.writeNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            xsw.writeAttribute("Version", "2.0");
            xsw.writeAttribute("ID", requestId);
            xsw.writeAttribute("IssueInstant", issueInstant);
            xsw.writeAttribute("AssertionConsumerServiceURL", getAssertionConsumerServiceUrl());
            String binding = getBinding();
            if ("urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect".equals(binding)) {
                xsw.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");//while WAAD supports the HTTP Redirect binding the binding value sent in the AuthNRequest must be the post binding.
            } else {
                xsw.writeAttribute("ProtocolBinding", binding);
            }

            xsw.writeStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            xsw.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            xsw.writeCharacters(getIssuer());
            xsw.writeEndElement();

            xsw.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");

            xsw.writeAttribute("Format", getNameIdFormat());
            xsw.writeAttribute("AllowCreate", "true");
            xsw.writeEndElement();

            xsw.writeEndElement();
            xsw.flush();
        } catch (XMLStreamException xe) {
            throw new IOException(xe);
        }
        String relayState = request.getRequestURL().toString();
        relayState = URLEncoder.encode(relayState, "UTF-8");
        String strRequest = null;
        SAMLBinding binding = null;
        switch (_binding) {
        case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
            StringBuilder sb = new StringBuilder();
            sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            sb.append("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\"");
            sb.append(" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">");
            sb.append("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n");
            sb.append("<body onload=\"document.forms[0].submit();\">\n");

            sb.append("<noscript>\n");
            sb.append("<p>\n");
            sb.append("<strong>Note:</strong> Since your browser does not support JavaScript, ");
            sb.append("you must press the Continue button once to proceed.");
            sb.append("</p>\n");
            sb.append("</noscript>\n");

            sb.append("<form action=\"");
            sb.append(getIdpURL());
            sb.append("\" ");
            sb.append("method=\"post\">\n");
            sb.append("<div>\n");
            if (relayState != null) {
                sb.append("<input type=\"hidden\" name=\"RelayState\" ");
                sb.append("value=\"");
                sb.append(relayState);
            }
            sb.append("\"/>\n");
            sb.append("<input type=\"hidden\" name=\"SAMLRequest\" ");
            sb.append("value=\"");
            sb.append(new String(B64Code.encode(xmlRequest.toString().getBytes())));
            sb.append("\"/>\n");
            sb.append("</div>\n");
            sb.append("<noscript>\n");
            sb.append("<div>\n");
            sb.append("<input type=\"submit\" value=\"Continue\"/>\n");
            sb.append("</div>\n");
            sb.append("</noscript>\n");
            sb.append("</form>\n");
            sb.append("</body>\n");
            sb.append("</html>\n");
            binding = SAMLBinding.POST;
            strRequest = sb.toString();
            break;
        case "urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect":
            byte[] binRequest = deflate(xmlRequest.toString().getBytes());
            strRequest = new String(B64Code.encode(binRequest));
            strRequest = URLEncoder.encode(strRequest, "UTF-8");
            binding = SAMLBinding.REDIRECT;
            break;
        case "urn:oasis:names:tc:SAML:2.0:bindings:SOAP":
            binding = SAMLBinding.ARTIFACT;
            break;
        default:
            throw new IOException("Unknown binding " + _binding);
        }
        return new SAMLRequest(binding, requestId, strRequest, relayState, getIdpURL());
    }

    @Override
    public SAMLRequest buildLogout(HttpServletRequest request, String nameId) throws IOException {
        String requestId = "id" + UUID.randomUUID().toString();
        SimpleDateFormat iidf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        String issueInstant = iidf.format(new Date());

        StringWriter xmlRequest = new StringWriter();
        //TODO support POST and Artifact Bindings. Currently only Request supported
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.newDocument();

            Element root = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:LogoutRequest");
            doc.appendChild(root);
            root.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            root.setAttribute("Version", "2.0");
            root.setAttribute("ID", requestId);
            root.setAttribute("IssueInstant", issueInstant);

            Element issuerNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:Issuer");
            root.appendChild(issuerNode);
            issuerNode.setTextContent(getIssuer());

            Element nameIdNode = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml:NameID");
            root.appendChild(nameIdNode);
            nameIdNode.setTextContent(nameId);
            nameIdNode.setAttribute("Format", getNameIdFormat());

            sign(doc, _keyPair);
            write(doc, xmlRequest);

        } catch (Exception xe) {
            throw new IOException(xe);
        }
        byte[] binRequest = deflate(xmlRequest.toString().getBytes());
        String strRequest = new String(B64Code.encode(binRequest));
        strRequest = URLEncoder.encode(strRequest, "UTF-8");
        SAMLBinding binding = null;
        switch (_binding) {
        case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
            binding = SAMLBinding.POST;
            break;
        case "urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect":
            binding = SAMLBinding.REDIRECT;
            break;
        case "urn:oasis:names:tc:SAML:2.0:bindings:SOAP":
            binding = SAMLBinding.ARTIFACT;
            break;
        default:
            throw new IOException("Unknown binding " + _binding);
        }
        return new SAMLRequest(binding, requestId, strRequest, null, getIdpURL());
    }

    public static byte[] deflate(byte[] request) throws IOException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);

        DeflaterOutputStream dos = new DeflaterOutputStream(bos, deflater);
        dos.write(request);
        dos.close();
        return bos.toByteArray();

    }

    public static void sign(Document doc, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, KeyException {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
        Transform transform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Reference reference = factory.newReference("", digestMethod, Collections.singletonList(transform), null, null);
        CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SignedInfo signedInfo = factory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));

        KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
        KeyValue keyValuePair = keyInfoFactory.newKeyValue(keyPair.getPublic());
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValuePair));

        DOMSignContext dsc = new DOMSignContext(keyPair.getPrivate(), doc.getDocumentElement());
        dsc.setNextSibling(doc.getDocumentElement().getFirstChild());

        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(dsc);

    }

    public static void write(Document doc, StringWriter writer) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
    }
}
