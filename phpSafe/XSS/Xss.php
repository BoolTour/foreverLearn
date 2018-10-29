<?php

class XSS
{
	/**
	*@desc 过滤数据
	*
	*@param $data String|array 输入数据
	*@param $low bool 是否采用更为严格的过滤
	*
	*@return 返回过滤的数据
	*/
	public function clean_xss($data, $low=true)
	{
		//字符串过滤
		if(!is_array($data))
		{
			$data = trim($data);            //去除字符串两边的空格
			$data = strip_tags($data);      //从字符串中去除 HTML 和 PHP 标记
			$data = htmlspecialchars($data);//特殊字符转换为HTML实体

			if(!$low)
			{
				return $data;
			}
		   //匹配换空格
           $data = str_replace ( array ('"', "\\", "'", "/", "..", "../", "./", "//" ), '', $data );
           $no = '/%0[0-8bcef]/'; 
           $data = preg_replace ( $no, '', $data );
           $no = '/%1[0-9a-f]/';
           $data = preg_replace ( $no, '', $data );
           $no = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';
           $data = preg_replace ( $no, '', $data );
           return $data;
		}
	   //数组过滤
	   $arr=array();
       foreach ($data as $k => $v) 
       {
           $temp=$this->clean_xss($v);
           $arr[$k]=$temp;
       }
       return $arr;
	}
}


//测试
session_start();
$_SESSION['xss']='xssss';
$xss=new XSS();
//测试字符串
$str = "<script>alert(document.cookie)</script>";
echo $str;
$str2=$xss->clean_xss($str);
echo "测试字符串过滤后:";
echo $str2;
echo "<hr/>";
//测试数组
$arr=array("<script>alert(document.cookie)</script>","<script>alert(document.cookie)</script>","<script>alert(document.cookie)</script>");
echo "<pre>";
print_r($arr);
echo "</pre>";
$arr2=$xss->clean_xss($arr);
echo "<pre>";
print_r($arr2);
echo "</pre>";