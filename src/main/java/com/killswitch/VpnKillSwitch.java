package com.killswitch;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class VpnKillSwitch implements BurpExtension {

    private Logging logging;
    private final AtomicBoolean killed = new AtomicBoolean(false);
    private volatile String targetInterface = "tun0";

    private JLabel statusLabel;
    private JButton resumeButton;
    private JTextField interfaceField;
    private ScheduledExecutorService scheduler;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        api.extension().setName("VPN Kill Switch");

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                if (killed.get()) {
                    logging.logToOutput("[BLOCKED] " + request.url());
                    return RequestToBeSentAction.drop();
                }
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                return ResponseReceivedAction.continueWith(response);
            }
        });

        JPanel panel = buildPanel();
        api.userInterface().registerSuiteTab("VPN Kill Switch", panel);

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "vpn-monitor");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::checkVpn, 0, 1, TimeUnit.SECONDS);

        api.extension().registerUnloadingHandler(scheduler::shutdownNow);

        logging.logToOutput("VPN Kill Switch loaded. Monitoring: " + targetInterface);
    }

    private void checkVpn() {
        if (killed.get()) return;
        if (!isInterfaceUp(targetInterface)) {
            arm("interface '" + targetInterface + "' is down");
        }
    }

    private boolean isInterfaceUp(String ifaceName) {
        try {
            NetworkInterface iface = NetworkInterface.getByName(ifaceName);
            return iface != null && iface.isUp();
        } catch (SocketException e) {
            return false; // fail-closed
        }
    }

    private void arm(String reason) {
        killed.set(true);
        logging.logToError("[VPN Kill Switch] ARMED — " + reason + " — all traffic blocked");
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("VPN DOWN — ALL TRAFFIC BLOCKED");
            statusLabel.setForeground(Color.RED);
            resumeButton.setEnabled(true);
        });
    }

    private void resume() {
        killed.set(false);
        logging.logToOutput("[VPN Kill Switch] Traffic resumed by user. Monitoring: " + targetInterface);
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("VPN UP — Monitoring: " + targetInterface);
            statusLabel.setForeground(new Color(0, 150, 0));
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
        statusLabel = new JLabel("VPN UP — Monitoring: tun0");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD, 13f));
        statusLabel.setForeground(new Color(0, 150, 0));
        panel.add(statusLabel, gbc);

        gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(new JLabel("VPN Interface:"), gbc);

        gbc.gridx = 1;
        interfaceField = new JTextField("tun0", 10);
        panel.add(interfaceField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JButton saveBtn = new JButton("Set Interface");
        saveBtn.addActionListener(e -> {
            String name = interfaceField.getText().trim();
            if (!name.isEmpty()) {
                targetInterface = name;
                if (!killed.get()) {
                    statusLabel.setText("VPN UP — Monitoring: " + name);
                }
                logging.logToOutput("Now monitoring interface: " + name);
            }
        });
        panel.add(saveBtn, gbc);

        gbc.gridy = 4;
        resumeButton = new JButton("Resume Traffic");
        resumeButton.setEnabled(false);
        resumeButton.setFont(resumeButton.getFont().deriveFont(Font.BOLD));
        resumeButton.setForeground(new Color(180, 0, 0));
        resumeButton.addActionListener(e -> resume());
        panel.add(resumeButton, gbc);

        gbc.gridy = 5;
        JTextArea desc = new JTextArea(
            "Polls VPN interface every 1 second.\n" +
            "If interface goes down, ALL outbound Burp traffic is dropped.\n" +
            "Scanner, Intruder, Repeater, and extensions are all blocked.\n" +
            "Click 'Resume Traffic' only after VPN is restored."
        );
        desc.setEditable(false);
        desc.setBackground(panel.getBackground());
        desc.setFont(desc.getFont().deriveFont(11f));
        panel.add(desc, gbc);

        return panel;
    }
}
