import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;

/** RASP agent 自检：正常对象应通过，黑名单类（bsh.Interpreter0）应被 REJECTED */
public class TestRasp {

    static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
        }
        return bos.toByteArray();
    }

    static Object deserialize(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    public static void main(String[] args) throws Exception {
        int pass = 0, fail = 0;

        // 用例1：正常对象必须放行
        try {
            Object o = deserialize(serialize(new ArrayList<>(Arrays.asList("hello", "world"))));
            if (o instanceof ArrayList && ((ArrayList<?>) o).size() == 2) {
                System.out.println("[PASS] 正常对象反序列化放行");
                pass++;
            } else {
                System.out.println("[FAIL] 正常对象内容不符");
                fail++;
            }
        } catch (Exception e) {
            System.out.println("[FAIL] 正常对象被误拦: " + e);
            fail++;
        }

        // 用例2：黑名单类必须被拦截
        try {
            byte[] payload = serialize(new bsh.Interpreter0());
            Object o = deserialize(payload);
            System.out.println("[FAIL] 黑名单类未被拦截: " + o.getClass().getName());
            fail++;
        } catch (InvalidClassException e) {
            System.out.println("[PASS] 黑名单类被拦截: " + e.getMessage());
            pass++;
        } catch (Exception e) {
            System.out.println("[FAIL] 黑名单类触发异常但非预期类型: " + e);
            fail++;
        }

        System.out.println("RESULT: pass=" + pass + " fail=" + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
