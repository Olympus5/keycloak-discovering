package fr.olympus5;

import org.jboss.logging.Logger;

public class LoggerUtils {
    public static void markMethodEntry(Class clazz, String methodName) {
        Logger.getLogger(clazz).infof("Hello from [ %s.%s ]", clazz.getSimpleName(), methodName);
    }
}
