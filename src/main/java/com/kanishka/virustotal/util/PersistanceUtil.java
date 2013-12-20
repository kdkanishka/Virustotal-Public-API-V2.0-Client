package com.kanishka.virustotal.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Created by kanishka on 12/12/13.
 */
public final class PersistanceUtil {

    private PersistanceUtil() {

    }

    public static void persist(Object object, File file) throws IOException {
        FileOutputStream fOutStream = new FileOutputStream(file);
        ObjectOutputStream objOutStr = new ObjectOutputStream(fOutStream);
        objOutStr.writeObject(object);
        fOutStream.close();
        objOutStr.close();
    }

    public static Object deSeralizeObject(File file) throws IOException, ClassNotFoundException {
        FileInputStream fInstr = new FileInputStream(file);
        ObjectInputStream objInstr = new ObjectInputStream(fInstr);
        Object obj = objInstr.readObject();
        fInstr.close();
        objInstr.close();
        return obj;
    }
}
