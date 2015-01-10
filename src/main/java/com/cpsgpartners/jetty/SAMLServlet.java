package com.cpsgpartners.jetty;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;

public class SAMLServlet extends HttpServlet {
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    final String greeting;
    final String body;

    public SAMLServlet() {
        this("Jetty Default SAML Handler");
    }

    public SAMLServlet(String greeting) {
        this(greeting, null);
    }

    public SAMLServlet(String greeting, String body) {
        this.greeting = greeting;
        this.body = body;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html; charset=utf-8");
        resp.setStatus(HttpServletResponse.SC_OK);

        PrintWriter out = resp.getWriter();

        out.println("<h1>" + greeting + "</h1>");
        if (body != null) {
            out.println(body);
        }

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

}
