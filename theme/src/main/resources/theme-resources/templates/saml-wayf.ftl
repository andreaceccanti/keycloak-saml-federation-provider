<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${provider} - Sign in with your IdP
    <#elseif section = "form">
        <form id="kc-form-saml-wayf" action="${actionUrl}" method="GET">
            <div class="${properties.kcFormGroupClass!}">
               <label for="idplist" class="${properties.kcLabelClass!}">${properties.wayfLabel}</label>
               <select id="idplist" name="idp" class="${properties.kcSelectClass!}">
               <#list descriptors as d>
                  <option value="${d.entityId}">${d.entityId}</option>
               </#list>
               </select>
            </div>
            <div class="form-group login-pf-settings">
               <div id="kc-form-options"></div>
               <div class=""></div>
            </div>
            <div class="${properties.kcFormGroupClass!}">
               <input type="hidden" name="provider" value="${provider}" />
               <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="wayf-login" id="kc-wayf-login" type="submit" value="${properties.wayfDoLogin}"/>
            </div>
        </form>
    </#if>

</@layout.registrationLayout>