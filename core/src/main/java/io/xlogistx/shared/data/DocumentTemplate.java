/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.shared.data;


import org.zoxweb.shared.data.SimpleDocumentDAO;
import org.zoxweb.shared.util.*;



/**
 * 
 * @author mzebib
 */
@SuppressWarnings("serial")
public class DocumentTemplate
	extends SimpleDocumentDAO
{

	public enum Param
		implements GetNVConfig
	{
		TAGS(NVConfigManager.createNVConfig("tags", "token tags", "TokenTags", true, true, NVStringList.class)),
		TITLE(NVConfigManager.createNVConfig("title", "Message title", "Title", true, true, String.class)),
		PRE_TAG(NVConfigManager.createNVConfig("pre_tag", "The pre token tag.", "PreTokenTag", false, true, String.class)),
		POST_TAG(NVConfigManager.createNVConfig("post_tag", "The post token tag.", "PostTokenTag", false, true, String.class)),

		;

        private final NVConfig nvc;

        Param(NVConfig nvc)
        {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig()
        {
            return nvc;
        }
	}

	public static final NVConfigEntity NVC_DOCUMENT_TEMPLATE = new NVConfigEntityLocal(
            "document_template",
            null,
            "DocumentTemplate",
            true,
            false,
            false,
            false,
			DocumentTemplate.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SimpleDocumentDAO.NVC_SIMPLE_DOCUMENT_DAO
    );


	/**
	 * The default constructor.
	 */
	public DocumentTemplate()
	{
		super(NVC_DOCUMENT_TEMPLATE);
	}
	

	
	/**
	 * Returns the message body tags.
	 * @return tags
	 */
	@SuppressWarnings("unchecked")
	public String[] getBodyTags()
	{		
		return ((NVStringList) lookup(Param.TAGS)).getValues();
	}
	
	/**
	 * Sets the message body tags.
	 * @param tags
	 */
	@SuppressWarnings("unchecked")
	public void setBodyTags(String ...tags)
	{
		NVStringList tagsList = (NVStringList) lookup(Param.TAGS);
		tagsList.setValues(tags);
	}	
	

	
	/**
	 * Returns the message title.
	 * @return title
	 */
	public String getTitle()
	{
		return lookupValue(Param.TITLE);
	}

	/**
	 * Sets the message title.
	 * @param title
	 */
	public void setTitle(String title)
	{
		setValue(Param.TITLE, title);
	}
	
	/**
	 * Returns the pre-token tag.
	 * @return pretag
	 */
	public String getPreTag() 
	{
		return  lookupValue(Param.PRE_TAG);
	}
	
	/**
	 * Sets the pre-token tag.
	 * @param preTokenTag
	 */
	public void setPreTag(String preTokenTag) 
	{
		setValue(Param.PRE_TAG, preTokenTag);
	}
	
	/**
	 * Returns the post-token tag.
	 * @return post tag
	 */
	public String getPostTag() 
	{
		return  lookupValue(Param.POST_TAG);
	}

	/**
	 * Sets the post-token tag.
	 * @param postTokenTag
	 */
	public void setPostTag(String postTokenTag)
	{
		setValue(Param.POST_TAG, postTokenTag);
	}
	
}