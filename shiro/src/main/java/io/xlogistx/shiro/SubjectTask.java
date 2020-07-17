/*
 * Copyright (c) 2012-2020 XlogistX.IO Corp.
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
package io.xlogistx.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.zoxweb.shared.util.SharedUtil;


public  class SubjectTask
        implements Runnable
{
    private final Subject subject;
    private final Runnable runnableBySubject;

    private SubjectTask(Runnable runnableBySubject, Subject subject)
    {
        this.subject = subject;
        this.runnableBySubject = runnableBySubject;
    }

    public static SubjectTask create(Runnable runnableBySubject)
    {
        return create(runnableBySubject, SecurityUtils.getSubject());
    }

    public static SubjectTask create(Runnable runnableBySubject, Subject subject)
    {
        SharedUtil.checkIfNulls("Runnable or Subject can't be null", runnableBySubject, subject);
        return new SubjectTask(runnableBySubject, subject);
    }

    public void run()
    {
        subject.execute(runnableBySubject);
    }

}
