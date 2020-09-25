/*
 * Copyright (c) 2017, Red Hat Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
package sk.upjs.tip.ciit.ais2test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.openjdk.jcstress.annotations.*;
import org.openjdk.jcstress.infra.results.ZZ_Result;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.wso2.carbon.identity.sso.agent.SAML2SSOAgentFilter;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509Credential;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509KeyStoreCredential;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;

// See jcstress-samples or existing tests for API introduction and testing guidelines

@JCStressTest
// Outline the outcomes here. The default outcome is provided, you need to remove it:
@Outcome(id = "false, false", expect = Expect.ACCEPTABLE, desc = "Default outcome.")
@Outcome(expect = Expect.FORBIDDEN, desc = "Other cases are not good.")
@State
public class IdentityAgentSSOStressTest {

	
	public IdentityAgentSSOStressTest() {

		// TODO Auto-generated constructor stub
		createMocks();
	}
	
	private static final String SSO_AGENT_CONFIG_ATTR_NAME = "org.wso2.carbon.identity.sso.agent.SSOAgentConfig";
	SSOAgentConfig ssoAgentConfig = createSsoAgentConfig();
	private SAML2SSOAgentFilter ssoAgentFilter = null;
	private MockFilterChain filterChain = null;
	
    public SSOAgentConfig createSsoAgentConfig(){
    	
    	SSOAgentConfig ssoAgentConfig = null;
    			
    	try {
    		Path ssoProps = Paths.get("src/test/resources/samlsso.properties");
    		Properties properties = new Properties();
    		properties.load(new FileInputStream(ssoProps.toFile().getAbsolutePath()));

    		Path keyStore = Paths.get("src/test/resources/keyStore.jks");
    		String keyStorePath = keyStore.toFile().getAbsolutePath();
    		InputStream keyStoreInputStream = new FileInputStream(keyStorePath);

    		SSOAgentX509Credential credential = new SSOAgentX509KeyStoreCredential(keyStoreInputStream,
    				properties.getProperty(SSOAgentConstants.KEY_STORE_PASSWORD).toCharArray(),
    				properties.getProperty(SSOAgentConstants.IDP_PUBLIC_CERT),
    				properties.getProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS),
    				properties.getProperty(SSOAgentConstants.PRIVATE_KEY_PASSWORD).toCharArray());

    		ssoAgentConfig = new SSOAgentConfig();
    		ssoAgentConfig.initConfig(properties);
    		//        ssoAgentConfig.setKeyStorePath(keyStorePath);
    		ssoAgentConfig.getSAML2().setSSOAgentX509Credential(credential);
    	} catch (IOException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (SSOAgentException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	}
    	return ssoAgentConfig;
    }
    
    public void createMocks() {
    	try {
    		MockServletContext servletContext = new MockServletContext();
    		servletContext.setAttribute( SSO_AGENT_CONFIG_ATTR_NAME, ssoAgentConfig );

    		FilterConfig filterConfig = new MockFilterConfig(servletContext);

    		ssoAgentFilter = new SAML2SSOAgentFilter();
    		ssoAgentFilter.init(filterConfig);

    		filterChain = new MockFilterChain();
    	} catch (ServletException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	}
    	
    }

	
	public void wrongAccess() {
		
		
		try {
			MockHttpServletRequest request = new MockHttpServletRequest( "POST", "http://www.localhost.org/ais/login.do");
	        MockHttpServletResponse response = new MockHttpServletResponse();

	        ssoAgentFilter.doFilter(request, response, filterChain);

		
		} catch (ServletException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	
	
    @Actor
    public void actor1(ZZ_Result r) {
    	wrongAccess();
    	r.r1 = ssoAgentConfig.getSAML2().isPassiveAuthn();  
    }

    @Actor
    public void actor2(ZZ_Result r) {
    	wrongAccess();
    	r.r2 = ssoAgentConfig.getSAML2().isPassiveAuthn();  
    }

}
