#pragma once

#include <string>
 
// #define DEBUG 0

#ifdef DEBUG
    #define LOG printf
#else
    #define LOG(...) while(0){}
#endif

template< typename T > class LinkedList
{
protected:
    struct Link
    {
        T data;
        Link *forward;
        Link *backward;
    };
    
    Link *front;
    Link *back;
public:
    LinkedList() : 
        front(nullptr),
        back(nullptr)
    {
        
    }
    ~LinkedList()
    {

    }

    void addBack( const T &data )
    {
        Link* appendMe = createLink( data );
        if(  nullptr != back ) 
        {
            Link *oldBack = back;
            // setup the new thing
            appendMe->forward = oldBack;
            appendMe->backward = nullptr;
            back = appendMe;
            // Fix the old thing
            oldBack->backward = appendMe;

        }
        else
        {
            appendMe->forward = nullptr;
            appendMe->backward = nullptr;
            front =  appendMe;
            back = appendMe;
        }
    }
    void addFront( const T &data )
    {
        Link* appendMe = createLink( data );
        if(  nullptr != front ) 
        {
            Link* oldFront = front;
            // Setup the new thing
            appendMe->forward = nullptr;
            appendMe->backward = oldFront;
            front = appendMe;
            // Fix the old thing
            oldFront->forward = appendMe;

        }
        else
        {
            appendMe->forward = nullptr;
            appendMe->backward = nullptr;
            front =  appendMe;
            back = appendMe;
        }
    }

    T* getFront( size_t offset=0 )
    {
        if( front == nullptr )
        {
            return nullptr;
        }
        return &front->data;
    }
    T* getBack( size_t offset=0 )
    {
        if( back == nullptr )
        {
            return nullptr;
        }
        return &back->data;
    }

    void popFront( )
    {
        Link *oldFront = front;

        // printf("Front Free: %#lx\n", oldFront );

        if( nullptr == front){
            return;
        }

        front = front->backward;
        if( nullptr != front )
        {
            front->forward = nullptr;
        }
        delete oldFront;
    }

    void popBack( )
    {
        Link *oldBack = back;

        // printf("Back Free: %#lx\n", oldBack );

        if( nullptr == back){
            return;
        }

        back = back->forward;
        if( nullptr != back )
        {
            back->backward = nullptr;
        }

        oldBack->backward = nullptr;
        oldBack->forward = nullptr;
        
        delete oldBack;
    }

    T* getIndex( size_t frontInd )
    {
        Link* current(nullptr);
        current = front;
        for( size_t k = 1 ; k <= frontInd ; k++ )
        {
            if( current->backward != nullptr )
            {
                current = current->backward; 
            }
            else
            {
                current = nullptr;
                break;
            }
        }
        if( current != nullptr )
        {
            return &current->data;
        }
        else
        {
            return nullptr;
        }
        
    } 
protected:
    Link* createLink( const T &data )
    {
        Link* newLink= new Link();

        // printf("NewNode: %#lx\n", newLink );

        newLink->data = data;
        return newLink;
    }


};