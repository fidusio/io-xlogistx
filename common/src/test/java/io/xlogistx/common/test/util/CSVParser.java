package io.xlogistx.common.test.util;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SharedUtil;

import java.io.FileReader;
import java.io.Reader;

public class CSVParser {

    public static void  main(String ...args)
    {
        try
        {
            int index = 0;
            String filename = args[index++];
            Reader in = new FileReader(filename);
            Iterable<CSVRecord> records = CSVFormat.RFC4180.withFirstRecordAsHeader().parse(in);

            int total = 0;
            int empty = 0;
            for (CSVRecord record : records) {
                String email = record.get("Email");
                if(SUS.isEmpty(email))
                    empty++;
                else
                    System.out.println(SharedUtil.toCanonicalID(',', record.get("First Name"), record.get("Last Name"), email));
                total++;
            }
            System.out.println("Total: " + total + " Empty: " + empty);

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
