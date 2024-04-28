/***************************************************************************** 
    *  @Copyright (c) 2019, musu
    *  @All rights reserved 
 
    *  @file     : singletonX.h 
    
    *  @date     : 2019/3/11 17:32 
    *  @brief    : 实现单例模板类
*****************************************************************************/ 

#ifndef  __FILE_SINGLETONX_H__
#define  __FILE_SINGLETONX_H__

#include <mutex>

//< dynamic
template <class T>
class Singleton
{
public:
	static T* GetInstance()
	{
		if (nullptr == s_instance)
		{
			s_mutex.lock();
			if (nullptr == s_instance)
			{
				s_instance = new T;
			}
			s_mutex.unlock();
		}

		return s_instance;
	}

	static void UnInstance()
	{
		if (nullptr != s_instance)
		{
			s_mutex.lock();
			if (nullptr != s_instance)
			{
				delete s_instance;
				s_instance = nullptr;
			}
			s_mutex.unlock();
		}
	}

	Singleton(const Singleton<T> &) = delete; //不实现 
	Singleton<T>& operator= (const Singleton<T> &) = delete; //不实现

protected:
	Singleton() {}
	virtual ~Singleton() {}

private:
	static T* s_instance;
	static std::mutex s_mutex;
};

template <class T>
T* Singleton<T>::s_instance = nullptr;

template <class T>
std::mutex Singleton<T>::s_mutex;

//////////////////////////////////////////////////////////////////////////
// class SingletonStatic
//////////////////////////////////////////////////////////////////////////
template <class T>
class SingletonStatic
{
public:
	static T* instance()
	{
		return &s_instance;
	}

	SingletonStatic(const SingletonStatic<T> &) = delete; //不实现 
	SingletonStatic<T>& operator= (const SingletonStatic<T> &) = delete; //不实现

protected:
	SingletonStatic() {}
	virtual ~SingletonStatic() {}

private:
	static T s_instance;
};

template <class T>
T SingletonStatic<T>::s_instance;

#endif
