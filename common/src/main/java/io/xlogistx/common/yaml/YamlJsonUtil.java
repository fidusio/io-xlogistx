package io.xlogistx.common.yaml;

import com.google.gson.Gson;
import org.yaml.snakeyaml.Yaml;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

public class YamlJsonUtil {

  public enum YamlJsonMode
  {
    Y2J,
    J2Y
  }


  private YamlJsonUtil(){};

  /**
   * Convert a yaml string to a json string
   * @param yamlString
   * @return
   */
  public static String yamlToJson(String yamlString)
  {
    Yaml yaml = new Yaml();
    Map<String, Object> obj = yaml.load(yamlString);
    Gson gson = new Gson();
    return gson.toJson(obj);
  }

  /**
   * convert a json string to yaml string
   * @param jsonString
   * @return
   */
  public static String jsonToYaml(String jsonString)
  {
    @SuppressWarnings("unchecked")
    Map<String, Object> map = new Gson().fromJson(jsonString, LinkedHashMap.class);
    return new Yaml().dump(map);
  }


  public static void main(String ...args)
  {
    int index = 0;

    try
    {
      YamlJsonMode mode = SharedUtil.lookupEnum(args[index++], YamlJsonMode.values());
      if(mode == null)
        throw new IllegalArgumentException("Invalid mode");
      String urlOrFile = args[index++];
      String outFilename = index < args.length ? args[index++] : null;

      InputStream is = null;
      try
      {
        // try to parse url
        URI uri = new URI(urlOrFile);
        is = uri.toURL().openStream();
      }
      catch(Exception e)
      {
        is = new FileInputStream(urlOrFile);
      }

      String content = IOUtil.inputStreamToString(is, true);
      String outContent = null;
      switch (mode)
      {
        case Y2J:
          outContent = YamlJsonUtil.yamlToJson(content);
          break;
        case J2Y:
          outContent = YamlJsonUtil.jsonToYaml(content);
          break;
      }

      if(outFilename != null)
      {
        try(FileOutputStream fos = new FileOutputStream(outFilename)) {
          fos.write(SharedStringUtil.getBytes(outContent));
          System.out.println(outFilename + " was created successfully");
        }

      }
      else
      {
        System.out.println(outContent);
      }


    }
    catch(Exception e)
    {
      System.err.println("usage: j2y/y2j url/file [dest-filename]");

      e.printStackTrace();
    }
  }


}