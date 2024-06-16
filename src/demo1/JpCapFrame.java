package demo1;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class JpCapFrame extends JFrame {
    //传入设备，用于选择
    NetworkInterface[] devices = JpcapCaptor.getDeviceList();


    private static DefaultTableModel model;
    private static JTextField filterField;
    private JTextArea showArea;
    private JButton startBtn;
    private JComboBox<String>checkBtn = new JComboBox<>();
    private JButton exitBtn;
    private JButton clearBtn;

    public JpCapFrame() {
        super();
        initGUI();
    }

    public static DefaultTableModel getModel() {
        return model;
    }

    public JTextArea getShowArea() {
        return showArea;
    }



    public JButton getStartBtn() {
        return startBtn;
    }

    public JComboBox<String> getCheckBtn() {
        return checkBtn;
    }

    public JButton getExitBtn() {
        return exitBtn;
    }

    public JButton getClearBtn() {
        return clearBtn;
    }

    public static JTextField getFilterField() {
        return filterField;
    }

    private void initGUI() {
        Font font1 = new Font("宋体", Font.BOLD, 15);
        Font font4 = new Font("宋体", Font.BOLD, 14);
        Font font2 = new Font("宋体", Font.PLAIN, 16);
        Font font3 = new Font("微软雅黑", Font.PLAIN, 16);

        //界面
        setSize(1550, 1000);
        setVisible(true);
        setTitle("抓了个抓");
        Container container = this.getContentPane();

        //顶部
        JPanel pane = new JPanel();
        pane.setBounds(0, 0, 775, 150);
        pane.setLayout(new FlowLayout(FlowLayout.LEFT, 10, 0));
        pane.setPreferredSize(new Dimension(775, 27));

        checkBtn = new JComboBox<String>();
        for (int i = 0; i < devices.length; i++) {
            checkBtn.addItem(devices[i].description);
        }
        checkBtn.setFont(font4);
        checkBtn.setBounds(0, 0, 50, 0);
        pane.add(checkBtn);

        startBtn = new JButton("开始");
        startBtn.setFont(font4);
        startBtn.setBounds(0, 0, 50, 0);
        pane.add(startBtn);

        clearBtn = new JButton("清空");
        clearBtn.setFont(font4);
        clearBtn.setBounds(0, 0, 50, 0);
        pane.add(clearBtn);

        exitBtn = new JButton("退出");
        exitBtn.setFont(font4);
        exitBtn.setBounds(0, 0, 50, 0);
        pane.add(exitBtn);

        JPanel panelTest = new JPanel();
        panelTest.setBounds(775, 0, 775, 150);
        panelTest.setPreferredSize(new Dimension(775, 27));
        panelTest.setLayout(new FlowLayout(FlowLayout.RIGHT, 20, 0));

        JLabel filter = new JLabel("Filter:");
        filter.setFont(font1);
        filter.setBounds(0, 0, 500, 0);
        filterField = new JTextField(50);
        filterField.setBounds(200, 0, 500, 0);
        panelTest.add(filter);
        panelTest.add(filterField);

        //中部主体内容显示区
        String[] name = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
        JTable table;
        model = new DefaultTableModel(name, 0);
        table = new JTable(model);
        table.setFont(font2);
        table.setRowHeight(20);
        table.setEnabled(false);
        JScrollPane jScrollPane = new JScrollPane(table);
        jScrollPane.setBounds(0, 300, 1550, 600);



        // 给表格的每一列添加点击事件监听器
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) { // 双击事件
                    // 获取点击的列的模型索引
                    int columnIndex = table.columnAtPoint(e.getPoint());
                    // 获取点击的列的标题
                    String columnTitle = table.getColumnName(columnIndex);
                    // 获取点击的行索引
                    int rowIndex = table.rowAtPoint(e.getPoint());
                    // 获取点击的列对应行的所有数据
                    Object[] rowData = new Object[table.getColumnCount()];
                    for (int i = 0; i < table.getColumnCount(); i++) {
                        rowData[i] = table.getValueAt(rowIndex, i);
                    }

                    // 创建一个新的窗口
                    JFrame newWindow = new JFrame("PackageInfo");
                    newWindow.setSize(400, 300);
                    newWindow.setVisible(true);

                    // 使用 JTextArea 显示数据
                    JTextArea detailArea = new JTextArea();
                    detailArea.setFont(new Font("宋体", Font.PLAIN, 12));
                    detailArea.setLineWrap(true); // 自动换行
                    detailArea.setWrapStyleWord(true); // 单词边界换行
                    JScrollPane detailScrollPane = new JScrollPane(detailArea);
                    newWindow.add(detailScrollPane, BorderLayout.CENTER);

                    // 设置数据到 JTextArea
                    StringBuilder detailText = new StringBuilder();
                    for (Object data : rowData) {
                        detailText.append(data).append("\t"); // 添加字段和值
                        if (data instanceof String) {
                            detailText.append("\n"); // 添加换行符
                        }
                    }
                    detailArea.setText(detailText.toString());

                    // 显示新窗口
                    newWindow.setVisible(true);
                }
            }
        });

        //底部
        JPanel pane2 = new JPanel();
        pane2.setLayout(new BorderLayout());
        pane2.setPreferredSize(new Dimension(1550, 300));

        showArea = new JTextArea(5, 5);
        showArea.setEditable(false);
        showArea.setLineWrap(false);
        showArea.setFont(font3);
        pane2.setSize(10, 10);
        pane2.setBounds(0, 0, 1, 1);
        //给textArea添加滚动条
        JScrollPane scrollPane = new JScrollPane(showArea);
        scrollPane.setBounds(0, 0, 1, 1);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        pane2.add(scrollPane, BorderLayout.CENTER);
        scrollPane.setViewportView(showArea);

        container.add(jScrollPane, BorderLayout.CENTER);
        container.add(pane, BorderLayout.NORTH);
        container.add(panelTest, BorderLayout.NORTH);
        container.add(pane2, BorderLayout.SOUTH);

        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    public int getInterface() {
        System.out.println(checkBtn.getSelectedIndex());
        return checkBtn.getSelectedIndex();
    }
}

