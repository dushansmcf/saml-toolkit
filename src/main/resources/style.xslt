<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:wxsl="https://www.w3schools.com/w3style.xsl">

    <xsl:namespace-alias stylesheet-prefix="saml2p" result-prefix="samlp"/>

    <xsl:template match="/">
        <xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>