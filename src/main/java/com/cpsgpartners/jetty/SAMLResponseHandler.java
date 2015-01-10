package com.cpsgpartners.jetty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.eclipse.jetty.util.B64Code;
//import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.cpsgpartners.jetty.SAMLAuthenticator.ResponseHandler;
import com.cpsgpartners.jetty.SAMLAuthenticator.SAMLNamespaceContext;
import com.cpsgpartners.jetty.SAMLAuthenticator.SAMLResponse;

public class SAMLResponseHandler implements ResponseHandler {

    private String _certificate;
    private X509Certificate _cert;
    private int _skewTime = 500;

    private String _roleAttribute;

    public String getCertificate() {
        return _certificate;
    }

    public void setCertificate(String certificate) throws CertificateException {
        this._certificate = certificate;
        ByteArrayInputStream bais = new ByteArrayInputStream(B64Code.decode(certificate));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        _cert = (X509Certificate) cf.generateCertificate(bais);
    }

    public int getSkewTime() {
        return _skewTime;
    }

    public void setSkewTime(int skewTime) {
        this._skewTime = skewTime;
    }

    public String getRoleAttribute() {
        return _roleAttribute;
    }

    public void setRoleAttribute(String roleAttribute) {
        _roleAttribute = roleAttribute;
    }

    @Override
    public SAMLResponse buildSAMLResponse(HttpServletRequest request, String assertion) throws IOException {
        try {
            byte[] binResponse = B64Code.decode(assertion);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(binResponse));

            XPathFactory xpf = XPathFactory.newInstance();
            XPath xp = xpf.newXPath();
            xp.setNamespaceContext(new SAMLNamespaceContext());

            Element root = doc.getDocumentElement();
            doc.getDocumentElement().normalize();

            String version = (String) xp.evaluate("@Version", root, XPathConstants.STRING);
            if (!"2.0".equals(version)) {
                throw new IOException(String.format("Unexpected version %s.", version));
            }           

            if ("".equals(xp.evaluate("@ID", root, XPathConstants.STRING))) {
                throw new IOException("Required ID attribute missing.");
            }
            
            String issueInstant = (String) xp.evaluate("@IssueInstant", root, XPathConstants.STRING);
            if ("".equals(issueInstant)) {
                throw new IOException("Required IssueInstant attribute missing.");
            }
            Calendar skewedTime = Calendar.getInstance();
            skewedTime.add(Calendar.SECOND, Math.abs(_skewTime) * -1);
            Calendar issueTime = DatatypeConverter.parseDateTime(issueInstant);
            if (issueTime.compareTo(skewedTime) < 0) {
                throw new IOException(String.format("IssueInstance %s has timed out with skewtime %d", issueInstant,_skewTime));
            }
            
            
            String inResponseTo = (String) xp.evaluate("@InResponseTo", root, XPathConstants.STRING);
            if ("".equals(inResponseTo)) {
                throw new IOException("Required InResponseTo attribute missing.");
            }

            if (!(Boolean) xp.evaluate("//samlp:StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']", root, XPathConstants.BOOLEAN)) {
                String statusCode = (String) xp.evaluate("(//samlp:StatusCode)[last()]/@Value", root, XPathConstants.STRING);
                String statusMessage = (String) xp.evaluate("//samlp:StatusMessage", root, XPathConstants.STRING);
                throw new IOException(String.format("unsuccessful status code: %s status message: %s", statusCode, statusMessage));
            }

            if (!(Boolean) xp.evaluate("//saml:Assertion", root, XPathConstants.BOOLEAN)) {
                throw new IOException("SAML Response must contain 1 Assertion.");
            }

            String name = (String) xp.evaluate("//saml:NameID", root, XPathConstants.STRING);
            if ("".equals(name)) {
                throw new IOException("Required NameID element missing.");
            }

            if (_cert == null) {
                throw new IOException("X509 certificate not set.");
            }

            Element signature = (Element) xp.evaluate("//dsig:Signature", root, XPathConstants.NODE);
            if (signature == null) {
                throw new IOException("Can't find signature in Document.");
            }

            DOMValidateContext ctx = new DOMValidateContext(_cert.getPublicKey(), signature);
            //https://bugs.openjdk.java.net/browse/JDK-8017169
            NodeList idAttributes = (NodeList) xp.evaluate("//*[@ID]", root, XPathConstants.NODESET);
            for (int i = 0; i < idAttributes.getLength(); i++) {
                ctx.setIdAttributeNS((Element) idAttributes.item(i), null, "ID");
            }

            XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
            XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);

            if (!xmlSignature.validate(ctx)) {
                throw new IOException("Signature is invalid.");
            }

            NodeList attributeNodes = (NodeList) xp.evaluate("//saml:Attribute", root, XPathConstants.NODESET);
            Map<String, List<String>> attributes = new HashMap<>();
            XPathExpression atVal = xp.compile("saml:AttributeValue");
            for (int i = 0; i < attributeNodes.getLength(); i++) {
                List<String> values = new ArrayList<>();
                attributes.put(((Element) attributeNodes.item(i)).getAttribute("Name"), values);
                NodeList valueNodes = (NodeList) atVal.evaluate(attributeNodes.item(i), XPathConstants.NODESET);
                for (int j = 0; j < valueNodes.getLength(); j++) {
                    values.add(((Element) valueNodes.item(j)).getTextContent());
                }
            }
            String[] roles = null;
            if (_roleAttribute != null) {
                List<String> roleList = attributes.get(_roleAttribute);
                if (roleList != null) {
                    roles = roleList.toArray(new String[roleList.size()]);
                }

            }

            return new SAMLResponse(doc, inResponseTo, name, roles, attributes, _cert);
        } catch (XPathException | ParserConfigurationException | SAXException | MarshalException | XMLSignatureException e) {
            throw new IOException(e);
        }
    }

}
