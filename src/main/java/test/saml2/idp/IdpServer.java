package test.saml2.idp;

import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.opensaml.saml2.core.Response;
import test.saml2.SamlToolkit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

class SamlRequestHandler extends AbstractHandler {
    @Override
    public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType("text/html;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        request.setHandled(true);
        PrintWriter pr = response.getWriter();
        String samlResponse = "";
        try {
            Response resp = SamlToolkit.createSamlResponse("cf31badf-b9e1-40bd-aac9-1ac8beda0283", "https://localhost/cf31badf-b9e1-40bd-aac9-1ac8beda0283/");
            samlResponse = SamlToolkit.toString(resp);
            samlResponse = SamlToolkit.encodeSAML_post(samlResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            pr.println(
                    "<html>" +
                            "<script>" +
                            "function post(path, params) {\n" +
                            "  const form = document.getElementById('xxx');\n" +
                            "  alert(form);\n" +
                            "  form.action = path;\n" +
                            "  form.submit();\n" +
                            "}\n" +
                            "</script>" +
                            "<body>" +
                            "<form method=\"post\" action=\"/post/\">\n" +
                            "<textarea id=\"w3review\" name=\"SAMLResponse\" rows=\"4\" cols=\"50\">\n" +
                            samlResponse +
                            "</textarea>\n" +
                            "<input type=\"submit\" vlaue=\"submitme\"/>\n" +
                            "</form>" +
                            "</body>" +
                            "</html>"
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DummyPost extends AbstractHandler {
    @Override
    public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse response) throws IOException, ServletException {
        if (request.getMethod().equalsIgnoreCase("POST")) {
            String samlResponse = request.getParameter("SAMLResponse");
            response.setContentType("text/plain;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            request.setHandled(true);
            PrintWriter pr = response.getWriter();

            try {
                samlResponse = SamlToolkit.decodeSAML_POST(samlResponse);
            } catch (Exception e) {
                e.printStackTrace();
            }

            pr.println(samlResponse);
        } else {
            response.sendError(405, "Not allowed");
        }
    }
}

public class IdpServer extends AbstractHandler {
    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request,
                       HttpServletResponse response) throws IOException, ServletException {
        response.setContentType("text/plain;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        baseRequest.setHandled(true);
        response.getWriter().println("Hello there");
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server();

        HttpConfiguration https = new HttpConfiguration();
        https.addCustomizer(new SecureRequestCustomizer());
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath("/home/sajith/scratch/saml-toolkit/src/main/resources/dev.localhost.jks");
        sslContextFactory.setKeyManagerPassword("123456");

        ContextHandler samlReqContext = new ContextHandler();
        samlReqContext.setContextPath("/saml");
        samlReqContext.setResourceBase(".");
        samlReqContext.setClassLoader(Thread.currentThread().getContextClassLoader());
        samlReqContext.setHandler(new SamlRequestHandler());

        ContextHandler postContext = new ContextHandler();
        postContext.setContextPath("/post");
        postContext.setResourceBase(".");
        postContext.setClassLoader(Thread.currentThread().getContextClassLoader());
        postContext.setHandler(new DummyPost());

        HandlerCollection handlerCollection = new HandlerCollection();
        handlerCollection.addHandler(samlReqContext);
        handlerCollection.addHandler(postContext);
        server.setHandler(handlerCollection);


        ServerConnector sslConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory(https));
        sslConnector.setPort(9998);
        server.setConnectors(new Connector[]{sslConnector});
        sslConnector.setHost("172.17.42.1");
        server.start();
    }
}