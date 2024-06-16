package demo1;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import javax.swing.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JpCapMain implements Runnable {
    JpCapFrame frame;
    JpcapCaptor jpcap = null;
    private static Thread thread = null;
    private static boolean pause = true;

    public JpCapMain() {
        //创建界面
        frame = new JpCapFrame();
        frame.setVisible(true);

        //绑定网络设备
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();

        int caplen = 1512;
        boolean promiscCheck = true;

        List<Integer> deviceselect =new ArrayList<Integer>();
        DefaultListModel<String> listModel = new DefaultListModel<>();


        for (int i = 0; i < devices.length; i++) {
            deviceselect.add(i);
            listModel.addElement(devices[i].name);
        }



        //选择硬件处，添加按钮映射
        frame.getCheckBtn().addActionListener(e -> {
           int device =frame.getInterface();
            frame.getShowArea().append("接口信息："+devices[device].name+"\n");
                try {
                    jpcap = JpcapCaptor.openDevice(devices[device], caplen, promiscCheck, 50);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
        });

        frame.getStartBtn().addActionListener(e -> {
            if (pause) {
                if (thread == null) {
                    frame.getShowArea().append("   开始抓包,抓取范围为：" + JpCapFrame.getFilterField().getText() + " ……\n");

                    System.out.println(JpCapFrame.getFilterField().getText());
                    thread = new Thread(this);
                    thread.setPriority(Thread.MIN_PRIORITY);
                    //thread.sleep(100);
                    thread.start();
                    pause = false;
                    frame.getStartBtn().setText("暂停");
                } else {
                    frame.getStartBtn().setText("暂停");
                    pause = false;
                    frame.getShowArea().append("   继续抓包,抓取范围为：" + JpCapFrame.getFilterField().getText() + " ……\n");
                    synchronized (thread) {
                        thread.notify();
                    }
                }
            } else {
                pause = true;
                frame.getStartBtn().setText("开始");
                frame.getShowArea().append("        暂停抓包\n");
            }
        });

        frame.getClearBtn().addActionListener(e -> {
            frame.getShowArea().setText("");
            frame.getModel().setRowCount(0);
        });

        frame.getExitBtn().addActionListener(e -> {
            System.exit(0);
        });
    }

    public static void main(String[] args) {
        new JpCapMain();
    }

    @Override
    public void run() {
        try {
            new JpCapPacket(jpcap).capture();
            thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static Thread getThread() {
        return thread;
    }

    public static boolean isPause() {
        return pause;
    }
}
