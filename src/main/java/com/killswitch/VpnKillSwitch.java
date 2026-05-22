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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class VpnKillSwitch implements BurpExtension {

    private Logging logging;

    // Start ARMED — disarm only after both IPs confirmed on init
    private final AtomicBoolean killed = new AtomicBoolean(true);

    private volatile String knownLocalIp = null;
    private volatile String knownPublicIp = null;
    private volatile String checkUrl = "https://ifconfig.me";

    private static final int PUBLIC_FAIL_THRESHOLD = 3;
    private static final int MAX_RESPONSE_LEN = 64;
    private static final Pattern IP_PATTERN =
        Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$");

    private final AtomicInteger publicIpFailures = new AtomicInteger(0);
    private final AtomicInteger threadCounter = new AtomicInteger(0);

    private volatile JLabel statusLabel;
    private volatile JLabel localIpLabel;
    private volatile JLabel publicIpLabel;
    private volatile JButton resumeButton;
    private volatile JTextField checkUrlField;
    private ScheduledExecutorService scheduler;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        api.extension().setName("VPN Kill Switch");

        // Handlers registered first while killed=true — no traffic leaks during init
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (killed.get()) {
                    logging.logToOutput("[BLOCKED] " + request.url());
                    // 192.0.2.1 is RFC 5737 TEST-NET — guaranteed unreachable,
                    // no listener can exist, no application data leaves the host
                    return RequestToBeSentAction.continueWith(
                        request.withService(HttpService.httpService("192.0.2.1", 80, false))
                    );
                }
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        });

        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
                if (killed.get()) return ProxyRequestReceivedAction.drop();
                return ProxyRequestReceivedAction.continueWith(request);
            }

            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
                if (killed.get()) return ProxyRequestToBeSentAction.drop();
                return ProxyRequestToBeSentAction.continueWith(request);
            }
        });

        api.userInterface().registerSuiteTab("VPN Kill Switch", buildPanel());

        scheduler = Executors.newScheduledThreadPool(2,
            r -> {
                Thread t = new Thread(r, "vpn-monitor-" + threadCounter.getAndIncrement());
                t.setDaemon(true);
                return t;
            });
        scheduler.scheduleAtFixedRate(this::checkLocalIp, 1, 1, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::checkPublicIp, 30, 30, TimeUnit.SECONDS);

        api.extension().registerUnloadingHandler(scheduler::shutdownNow);

        // IP detection off the loader thread — disarms once both succeed
        Thread initThread = new Thread(this::initIps, "vpn-init");
        initThread.setDaemon(true);
        initThread.start();
    }

    private void initIps() {
        String localIp = getLocalOutboundIp();
        String publicIp = fetchPublicIp();

        if (localIp != null && publicIp != null) {
            knownLocalIp = localIp;
            knownPublicIp = publicIp;
            killed.set(false);
            logging.logToOutput("VPN Kill Switch ready. Local: " + localIp + " | Public: " + publicIp);
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("OK — All clear");
                statusLabel.setForeground(new Color(0, 150, 0));
                localIpLabel.setText("Local IP:  " + localIp);
                publicIpLabel.setText("Public IP: " + publicIp);
                resumeButton.setEnabled(false);
            });
        } else {
            // Stay armed — user must manually resume after connecting VPN
            logging.logToError("[VPN Kill Switch] Init failed (local=" + localIp
                + " public=" + publicIp + ") — staying armed");
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("INIT FAILED — ALL TRAFFIC BLOCKED");
                statusLabel.setForeground(Color.RED);
                resumeButton.setEnabled(true);
            });
        }
    }

    // Wrapped in try/catch — any uncaught exception in a ScheduledExecutor
    // silently cancels all future runs, which would disable monitoring entirely
    private void checkLocalIp() {
        try {
            if (killed.get()) return;
            String current = getLocalOutboundIp();
            if (current == null || !current.equals(knownLocalIp)) {
                arm("local IP changed from " + knownLocalIp + " to " + current);
            }
        } catch (Exception e) {
            arm("local IP check threw: " + e.getMessage());
        }
    }

    private void checkPublicIp() {
        try {
            if (killed.get()) return;
            String current = fetchPublicIp();
            if (current == null) {
                int f = publicIpFailures.incrementAndGet();
                logging.logToOutput("[VPN Kill Switch] Public check failed (" + f + "/" + PUBLIC_FAIL_THRESHOLD + ")");
                if (f >= PUBLIC_FAIL_THRESHOLD) {
                    arm("public IP unreachable for " + PUBLIC_FAIL_THRESHOLD + " checks");
                }
            } else {
                publicIpFailures.set(0);
                if (!current.equals(knownPublicIp)) {
                    arm("public IP changed from " + knownPublicIp + " to " + current);
                }
            }
        } catch (Exception e) {
            arm("public IP check threw: " + e.getMessage());
        }
    }

    private String getLocalOutboundIp() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            InetAddress addr = socket.getLocalAddress();
            // Wildcard 0.0.0.0 means routing lookup failed — treat as no IP
            if (addr == null || addr.isAnyLocalAddress()) return null;
            return addr.getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    private String fetchPublicIp() {
        String url = checkUrl;
        if (url == null || !url.startsWith("https://")) {
            logging.logToError("[VPN Kill Switch] Rejected check URL: " + url);
            return null;
        }

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection(Proxy.NO_PROXY);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "curl/7.0");

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line = reader.readLine();
                if (line == null) return null;
                String ip = line.trim();
                if (ip.length() > MAX_RESPONSE_LEN) return null;
                if (!IP_PATTERN.matcher(ip).matches()) {
                    logging.logToOutput("[VPN Kill Switch] Response is not an IP: "
                        + ip.substring(0, Math.min(ip.length(), 20)));
                    return null;
                }
                return ip;
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private void arm(String reason) {
        // compareAndSet prevents duplicate log/UI updates from concurrent checks
        if (killed.compareAndSet(false, true)) {
            logging.logToError("[VPN Kill Switch] ARMED — " + reason + " — all traffic blocked");
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("IP CHANGED — ALL TRAFFIC BLOCKED");
                statusLabel.setForeground(Color.RED);
                resumeButton.setEnabled(true);
            });
        }
    }

    private void resume() {
        // Blocking network I/O off the EDT to avoid freezing Burp UI
        new Thread(() -> {
            String localIp = getLocalOutboundIp();
            String publicIp = fetchPublicIp();

            if (localIp == null || publicIp == null) {
                logging.logToError("[VPN Kill Switch] Resume failed — VPN not ready. Local: "
                    + localIp + " | Public: " + publicIp);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("RESUME FAILED — VPN not ready");
                    statusLabel.setForeground(Color.RED);
                    resumeButton.setEnabled(true);
                });
                return;
            }

            knownLocalIp = localIp;
            knownPublicIp = publicIp;
            publicIpFailures.set(0);
            killed.set(false);
            logging.logToOutput("[VPN Kill Switch] Resumed. Local: " + localIp + " | Public: " + publicIp);
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("OK — All clear");
                statusLabel.setForeground(new Color(0, 150, 0));
                localIpLabel.setText("Local IP:  " + localIp);
                publicIpLabel.setText("Public IP: " + publicIp);
                resumeButton.setEnabled(false);
            });
        }, "vpn-resume") {{ setDaemon(true); }}.start();
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
        statusLabel = new JLabel("Initializing...");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 13f));
        statusLabel.setForeground(Color.ORANGE);
        panel.add(statusLabel, gbc);

        gbc.gridy = 2;
        localIpLabel = new JLabel("Local IP:  detecting...");
        localIpLabel.setFont(localIpLabel.getFont().deriveFont(Font.PLAIN, 12f));
        panel.add(localIpLabel, gbc);

        gbc.gridy = 3;
        publicIpLabel = new JLabel("Public IP: detecting...");
        publicIpLabel.setFont(publicIpLabel.getFont().deriveFont(Font.PLAIN, 12f));
        panel.add(publicIpLabel, gbc);

        gbc.gridy = 4; gbc.gridwidth = 1;
        panel.add(new JLabel("Check URL:"), gbc);

        gbc.gridx = 1;
        checkUrlField = new JTextField(checkUrl, 28);
        panel.add(checkUrlField, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        JButton setBtn = new JButton("Set URL");
        setBtn.addActionListener(e -> {
            String val = checkUrlField.getText().trim();
            if (val.startsWith("https://")) {
                checkUrl = val;
                logging.logToOutput("Check URL updated: " + checkUrl);
            } else {
                logging.logToError("[VPN Kill Switch] Rejected URL — must start with https://");
            }
        });
        panel.add(setBtn, gbc);

        gbc.gridy = 6;
        resumeButton = new JButton("Resume Traffic");
        resumeButton.setEnabled(true);
        resumeButton.setFont(resumeButton.getFont().deriveFont(Font.BOLD));
        resumeButton.setForeground(new Color(180, 0, 0));
        resumeButton.addActionListener(e -> {
            resumeButton.setEnabled(false);
            statusLabel.setText("Verifying VPN...");
            statusLabel.setForeground(Color.ORANGE);
            resume();
        });
        panel.add(resumeButton, gbc);

        gbc.gridy = 7;
        JTextArea desc = new JTextArea(
            "Starts ARMED — disarms only after both IPs are confirmed.\n" +
            "Local IP checked every 1s (routing table, no network call).\n" +
            "Public IP checked every 30s via HTTPS — bypasses Burp proxy.\n" +
            "Either change arms immediately. 3 public failures → arm.\n" +
            "Click 'Resume Traffic' only after VPN is fully restored."
        );
        desc.setEditable(false);
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);
        desc.setBackground(panel.getBackground());
        desc.setFont(desc.getFont().deriveFont(11f));
        panel.add(desc, gbc);

        return panel;
    }
}
