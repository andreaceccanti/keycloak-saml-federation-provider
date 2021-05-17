<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        SAML Aggregate WAYF
    <#elseif section = "form">
        Provider: ${provider}
        Test: ${test}
        <a href="http://dev.local.io:8081/auth/realms/test1/broker/saml-idp-test-aggregate/login?&entity_id=https%3A%2F%2Fidp.infn.it%2Fsaml2%2Fidp%2Fmetadata.php&client_id=${clientId}&tab_id=${tabId}&session_code=${sessionCode}">LOGIN</a>
    </#if>
</@layout.registrationLayout>