package io.xlogistx.common.data;

import org.zoxweb.shared.util.Appointment;

import java.security.SecureRandom;

public final class Challenge {


    public static final SecureRandom SR = new SecureRandom();
    public enum Type
    {
        ADDITION,
        SUBTRACTION,
        CAPTCHA
    }

    public enum Status
    {
        VALID,
        INVALID,
        MISSING_CORRELATION,
        ERROR
    }

    private final long result;
    private final String preText;
    private final Type type;
    private final String id;



    private Appointment appointment;
    private Challenge(String preText, Type type, long result, String id)
    {
        this.preText = preText;
        this.type = type;
        this.result = result;
        this.id = id;
    }

    public Type getType()
    {
        return type;
    }
    public long getResult()
    {
        return result;
    }

    public String getId()
    {
        return id;
    }

    public String format()
    {
        return preText;
    }


    public String toString()
    {
        return id + " " + result;
    }


    public static Challenge generate(Type type, int power, String id)
    {
        long num1;
        long num2;
        long result;
        Challenge ret = null;
        switch(type)
        {
            case ADDITION:
                num1 = Math.abs(SR.nextLong() % (long) Math.pow(10, power));
                num2 = Math.abs(SR.nextLong() % (long) Math.pow(10, power));
                result = num1 + num2;
                ret = new Challenge("Resolve Captcha Addition: " + num1 + " + " + num2 + " ", type, result, id);
                break;
            case SUBTRACTION:
                num1 = Math.abs(SR.nextLong() % (long) Math.pow(10, power));
                num2 = Math.abs(SR.nextLong() % (long) Math.pow(10, power));
                result = num1 - num2;
                ret = new Challenge("Resolve Captcha Substraction: " + num1 + " - " + num2 + " ", type,result, id);
                break;
            case CAPTCHA:
                result = Math.abs(SR.nextLong() % (long) Math.pow(10, power));
                ret = new Challenge("Enter Captcha Value: " + result + " ", type,result, id);
                break;
        }

        return ret;
    }
    Appointment getAppointment() {
        return appointment;
    }
    void setAppointment(Appointment appointment) {
        this.appointment = appointment;
    }

}
