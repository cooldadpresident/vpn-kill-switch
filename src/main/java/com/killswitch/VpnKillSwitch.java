package com.killswitch;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class VpnKillSwitch implements BurpExtension {

    private Logging logging;
    private final AtomicBoolean killed = new AtomicBoolean(false);

    private volatile String knownLocalIp = null;
    private volatile String knownPublicIp = null;
    private volatile String checkUrl = "http://ifconfig.me";

    // Arm after this many consecutive public IP check failures
    private static final int PUBLIC_FAIL_THRESHOLD = 3;
    private final AtomicInteger publicIpFailures = new AtomicInteger(0);

    private JLabel statusLabel;
    private JLabel localIpLabel;
    private JLabel publicIpLabel;
    private JButton resumeButton;
    private JTextField checkUrlField;
    private ScheduledExecutorService scheduler;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        api.extension().setName("VPN Kill Switch");

        // Block all HTTP tool traffic (Repeater, Scanner, Intruder, etc.)
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (killed.get()) {
                    logging.logToOutput("[BLOCKED] " + request.url());
                    // Redirect to unreachable loopback — connection refused, never reaches target
                    return RequestToBeSentAction.continueWith(
                        request.withService(HttpService.httpService("127.0.0.1", 19999, false))
                    );
                }
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        });

        // Drop proxy traffic cleanly (browser traffic through Burp listener)
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
                if (killed.get()) {
                    return ProxyRequestReceivedAction.drop();
                }
                return ProxyRequestReceivedAction.continueWith(request);
            }

            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
                return ProxyRequestToBeSentAction.continueWith(request);
            }
        });

        knownLocalIp = getLocalOutboundIp();
        knownPublicIp = fetchPublicIp();

        JPanel panel = buildPanel();
        api.userInterface().registerSuiteTab("VPN Kill Switch", panel);

        // Two-thread pool: local (1s) + public (30s) checks run independently
        scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "vpn-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::checkLocalIp, 1, 1, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::checkPublicIp, 30, 30, TimeUnit.SECONDS);

        api.extension().registerUnloadingHandler(scheduler::shutdownNow);

        logging.logToOutput("VPN Kill Switch loaded. Local: " + knownLocalIp + " | Public: " + knownPublicIp);
    }

    // Fast check — local routing table, no network call, runs every 1s
    private void checkLocalIp() {
        if (killed.get()) return;
        String current = getLocalOutboundIp();
        if (current == null || !current.equals(knownLocalIp)) {
            arm("local IP changed from " + knownLocalIp + " to " + current);
        }
    }

    // Slow check — actual public IP, runs every 30s; tolerates up to 3 consecutive failures
    private void checkPublicIp() {
        if (killed.get()) return;
        String current = fetchPublicIp();
        if (current == null) {
            int failures = publicIpFailures.incrementAndGet();
            logging.logToOutput("[VPN Kill Switch] Public IP check failed (" + failures + "/" + PUBLIC_FAIL_THRESHOLD + ")");
            if (failures >= PUBLIC_FAIL_THRESHOLD) {
                arm("public IP unreachable for " + PUBLIC_FAIL_THRESHOLD + " consecutive checks");
            }
        } else {
            publicIpFailures.set(0);
            if (!current.equals(knownPublicIp)) {
                arm("public IP changed from " + knownPublicIp + " to " + current);
            }
        }
    }

    // No network packet sent — OS routing table lookup only
    private String getLocalOutboundIp() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            return socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    // Bypasses Burp proxy via Proxy.NO_PROXY — uses Java native HTTP stack
    private String fetchPublicIp() {
        try {
            HttpURLConnection conn = (HttpURLConnection)
                new URL(checkUrl).openConnection(Proxy.NO_PROXY);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "curl/7.0");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                return reader.readLine().trim();
            }
        } catch (Exception e) {
            return null;
        }
    }

    private void arm(String reason) {
        killed.set(true);
        logging.logToError("[VPN Kill Switch] ARMED — " + reason + " — all traffic blocked");
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("IP CHANGED — ALL TRAFFIC BLOCKED");
            statusLabel.setForeground(Color.RED);
            resumeButton.setEnabled(true);
        });
    }

    private void resume() {
        knownLocalIp = getLocalOutboundIp();
        knownPublicIp = fetchPublicIp();
        publicIpFailures.set(0);
        killed.set(false);
        logging.logToOutput("[VPN Kill Switch] Resumed. Local: " + knownLocalIp + " | Public: " + knownPublicIp);
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("OK — All clear");
            statusLabel.setForeground(new Color(0, 150, 0));
            localIpLabel.setText("Local IP:  " + knownLocalIp);
            publicIpLabel.setText("Public IP: " + knownPublicIp);
            resumeButton.setEnabled(false);
        });
    }

    private JPanel buildPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(6, 6, 6, 6);

        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        JLabel title = new JLabel("VPN Kill Switch");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
        panel.add(title, gbc);

        gbc.gridy = 1;
        boolean armed = knownLocalIp == null || knownPublicIp == null;
        statusLabel = new JLabel(armed ? "NO IP — ALL TRAFFIC BLOCKED" : "OK — All clear");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 13f));
        statusLabel.setForeground(armed ? Color.RED : new Color(0, 150, 0));
        panel.add(statusLabel, gbc);

        gbc.gridy = 2;
        localIpLabel = new JLabel("Local IP:  " + (knownLocalIp != null ? knownLocalIp : "unknown"));
        localIpLabel.setFont(localIpLabel.getFont().deriveFont(Font.PLAIN, 12f));
        panel.add(localIpLabel, gbc);

        gbc.gridy = 3;
        publicIpLabel = new JLabel("Public IP: " + (knownPublicIp != null ? knownPublicIp : "unknown"));
        publicIpLabel.setFont(publicIpLabel.getFont().deriveFont(Font.PLAIN, 12f));
        panel.add(publicIpLabel, gbc);

        gbc.gridy = 4; gbc.gridwidth = 1;
        panel.add(new JLabel("Check URL:"), gbc);

        gbc.gridx = 1;
        checkUrlField = new JTextField(checkUrl, 25);
        panel.add(checkUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        JButton setBtn = new JButton("Set URL");
        setBtn.addActionListener(e -> {
            String val = checkUrlField.getText().trim();
            if (!val.isEmpty()) {
                checkUrl = val;
                logging.logToOutput("Check URL updated: " + checkUrl);
            }
        });
        panel.add(setBtn, gbc);

        gbc.gridy = 6;
        resumeButton = new JButton("Resume Traffic");
        resumeButton.setEnabled(armed);
        resumeButton.setFont(resumeButton.getFont().deriveFont(Font.BOLD));
        resumeButton.setForeground(new Color(180, 0, 0));
        resumeButton.addActionListener(e -> resume());
        panel.add(resumeButton, gbc);

        gbc.gridy = 7;
        JTextArea desc = new JTextArea(
            "Local IP checked every 1s (routing table, no network call).\n" +
            "Public IP checked every 30s via external URL (bypasses Burp).\n" +
            "Either change arms the kill switch immediately.\n" +
            "Public check: arms after 3 consecutive failures.\n" +
            "Click 'Resume Traffic' only after VPN is confirmed restored."
        );
        desc.setEditable(false);
        desc.setBackground(panel.getBackground());
        desc.setFont(desc.getFont().deriveFont(11f));
        panel.add(desc, gbc);

        return panel;
    }
}
