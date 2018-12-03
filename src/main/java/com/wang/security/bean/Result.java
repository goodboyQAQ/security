package com.wang.security.bean;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class Result<T> {
    private boolean success;
    private String msg;
    private List<T> data;

    public Result(boolean success,String msg){
        this.success=success;
        this.msg=msg;
    }
}
