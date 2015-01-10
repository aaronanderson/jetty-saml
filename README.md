jetty-saml
----

Streamlined [Jetty](http://eclipse.org/jetty/) extension to support [SAML](http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) [SP](http://en.wikipedia.org/wiki/Service_provider) SSO. It is a minimal implementations with no outside dependencies beyond the JVM and Jetty. This extension has been tested with Windows Azure Active Directory ([WAAD](http://azure.microsoft.com/en-us/services/active-directory/)) as the [IDP](http://en.wikipedia.org/wiki/Identity_provider)

----
## Windows Azure Setup

1. Create an Azure account. 

2. Once the account is registered an Active Directory instance will be available. Click on it.

3. On the top tab click applications. At the very bottom click the add button.

4.  Enter in the application's URL that will be receiving the SAML POST assertion. The Jetty authenticator will look for the presence of SAML parameters so you may use any web application URL. For multiple web applications deployed to the same Jetty instance a place holder SAML servlet is provided.
    
5. Select the application and click the Endpoints button at the bottom. Observe the Federation Metadata and SAML-P URLs.

----
## Jetty Setup
1. Place the jar file in the Jetty server classpath

2. Configure Jetty to utilize the extension. the provided jetty-saml-context.xml file can be used as a guideline. 

The main elements are the SAMLLoginService which retrieves user profile information from the SAML assertion. It could be extended to retrieve additional suplementary information from a local user store.
```XML
<New class="com.cpsgpartners.jetty.SAMLLoginService"/>
```

and the primary SamlAuthenticator component that supports the SAML 2.0 protocols and performs the Jetty authentication. This component needs further configuration to support the required SAML authentication environment.

```XML
	<New class="com.cpsgpartners.jetty.SAMLAuthenticator">
		...
		<Set name="requestHandler">
			<New class="com.cpsgpartners.jetty.SAMLRequestHandler">
				...
			</New>
		</Set>
		<Set name="responseHandler">
			<New class="com.cpsgpartners.jetty.SAMLResponseHandler">
				...
			</New>
		</Set>
	</New>	
		
```
  

The plugin can be used in two ways:

1. Single application
... This is the standard configuration where the extension is configured per web application using a jetty-context.xml file. In this case the jetty-saml.xml file is not needed. 

2. Multiple applications
... This allows muliple applications deployed to the same Jetty server to share authentication information. Per the JavaEE spec Jetty does not share session state between contexts. However if multiple applications are deployed to the same Jetty server it is desirable to have a single SAML configuration rather than maintaining multiple configurations. Include the jetty-saml.xml in the server configuration at startup. This file contains the main SAML configuration definitions and a minimal Servlet mapped to the /saml URL pattern which is intended to centrally receive SAML response requests. 




**Note the following restrictions:** 

1. Microsoft at the moment supports the SAML HTTP Redirect binding and they are working on support for the POST binding.

2. WAAD has it's own entitlements service based on oAuth 2 and as far as I know there is no way to configure WAAD to pass role information in the SAML request. Usually an application will use it's own local role and authorization data anyway. The SAMLLoginService could be extended to read role information from a user store.

3. The extension fully supports the SAML HTTP-Request profile and has initial support for the POST, Artifact, and Logout included but untested.

4. Jetty is designed to run applications in isolation and there is no clean way to centrally share components. The shared authentication feature uses static singletons and a WeakHashMap to pass authentication information between applications. Due to a desire to minimize dependencies this implementation is primitive and may not be suitable for production use.